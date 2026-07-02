// Local mirror of the authoritative Rust `AgentTextStreamTranscriptV1`
// (`crates/traits/src/agent_text_stream.rs`) and the UTF-8 chunk splitter
// (`transport_quic_stream::split_text_deltas`).
//
// dm-agent validates the `transcript_hash_hex` / `chunk_count` we send in
// `stream_finalize` against its own locally-composed transcript and REJECTS a
// finalize on any mismatch (see `crates/agent-connector/src/stream.rs`). So
// this file must reproduce the Rust hashing byte-for-byte: the same SHA-256
// chaining, the same QUIC-varint length prefixes in the seed, and the same
// chunk boundaries. Parity is locked by `test/transcript.test.ts` against
// vectors generated from the Rust implementation.
//
// NOTE: the shipped Hermes Python shim uses an 8-byte big-endian length prefix
// here instead of a QUIC varint; do not copy that — it does not match the Rust
// contract this file targets.

import { createHash, type Hash } from "node:crypto";

export const AGENT_TEXT_STREAM_RECORD_TEXT_DELTA = 0x01;
export const AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA = 0x02;
export const AGENT_TEXT_STREAM_RECORD_STATUS = 0x03;
export const AGENT_TEXT_STREAM_RECORD_CHECKPOINT = 0x04;
export const AGENT_TEXT_STREAM_RECORD_ABORT = 0x05;
export const AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE = 0x06;

/**
 * Default preview chunk size. Must equal dm-agent's `STREAM_COMPOSE_CHUNK_BYTES`
 * (1024) so our chunk boundaries — and therefore the transcript hash and chunk
 * count — match what the connector composes. dm-agent actually uses
 * `min(requested, group max_plaintext_frame_len)`; with the default 65503-byte
 * cap that is 1024. Previews in a group whose agent-text-stream policy caps the
 * plaintext frame below this value would re-chunk smaller on the connector side
 * and fail the finalize hash check; such groups should fall back to final-only.
 */
export const DEFAULT_STREAM_CHUNK_BYTES = 1024;

const TRANSCRIPT_HASH_CONTEXT = Buffer.from(
  "marmot agent text stream transcript v1",
  "utf8",
);

/**
 * QUIC variable-length integer encoding (RFC 9000 §16) — the length prefix the
 * Rust transcript seed uses for the stream id and start-event id. For a 32-byte
 * id this is the single byte `0x20`.
 */
export function encodeQuicVarint(value: number): Buffer {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError("QUIC varint value must be a non-negative integer");
  }
  if (value <= 63) {
    return Buffer.from([value]);
  }
  if (value <= 16383) {
    const out = Buffer.alloc(2);
    out.writeUInt16BE(value);
    out[0] = (out[0] ?? 0) | 0x40;
    return out;
  }
  if (value <= 1073741823) {
    const out = Buffer.alloc(4);
    out.writeUInt32BE(value);
    out[0] = (out[0] ?? 0) | 0x80;
    return out;
  }
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  out[0] = (out[0] ?? 0) | 0xc0;
  return out;
}

/**
 * Split text into append-only UTF-8 delta chunks, never breaking a code point.
 * A single code point larger than `maxChunkBytes` is emitted as its own chunk.
 * Exact port of `transport_quic_stream::split_text_deltas`.
 */
export function splitTextDeltas(text: string, maxChunkBytes: number): Buffer[] {
  if (!Number.isInteger(maxChunkBytes) || maxChunkBytes <= 0) {
    throw new RangeError("maxChunkBytes must be a positive integer");
  }
  if (text.length === 0) {
    return [];
  }

  const chunks: Buffer[] = [];
  let current = "";
  let currentLen = 0;
  for (const ch of text) {
    const chLen = Buffer.byteLength(ch, "utf8");
    if (current.length > 0 && currentLen + chLen > maxChunkBytes) {
      chunks.push(Buffer.from(current, "utf8"));
      current = "";
      currentLen = 0;
    }
    if (current.length === 0 && chLen > maxChunkBytes) {
      chunks.push(Buffer.from(ch, "utf8"));
      continue;
    }
    current += ch;
    currentLen += chLen;
  }
  if (current.length > 0) {
    chunks.push(Buffer.from(current, "utf8"));
  }
  return chunks;
}

function hashLenPrefixed(hasher: Hash, bytes: Buffer | Uint8Array): void {
  hasher.update(encodeQuicVarint(bytes.length));
  hasher.update(bytes);
}

/**
 * Append-only transcript accumulator matching Rust `AgentTextStreamTranscriptV1`.
 * Sequence numbers run from 1 and increment per appended chunk across all
 * record types, in send order.
 */
export class AgentTextStreamTranscript {
  private hash: Buffer;
  private nextSeq = 1;
  private count = 0;

  constructor(streamId: Buffer | Uint8Array, startEventId: Buffer | Uint8Array) {
    const hasher = createHash("sha256");
    hasher.update(TRANSCRIPT_HASH_CONTEXT);
    hashLenPrefixed(hasher, streamId);
    hashLenPrefixed(hasher, startEventId);
    this.hash = hasher.digest();
  }

  /** Low-level chained append, mirroring `AgentTextStreamTranscriptV1::append`. */
  appendRaw(seq: number, recordType: number, frame: Buffer | Uint8Array): void {
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(BigInt(seq));
    const hasher = createHash("sha256");
    hasher.update(this.hash);
    hasher.update(seqBuf);
    hasher.update(Buffer.from([recordType & 0xff]));
    hasher.update(frame);
    this.hash = hasher.digest();
    this.count += 1;
  }

  /** Chunk `text` and append each chunk as `recordType`, advancing the sequence. */
  appendRecord(
    recordType: number,
    text: string,
    chunkBytes: number = DEFAULT_STREAM_CHUNK_BYTES,
  ): void {
    for (const chunk of splitTextDeltas(text, chunkBytes)) {
      this.appendRaw(this.nextSeq, recordType, chunk);
      this.nextSeq += 1;
    }
  }

  appendText(text: string, chunkBytes?: number): void {
    this.appendRecord(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, text, chunkBytes);
  }

  appendStatus(status: string, chunkBytes?: number): void {
    this.appendRecord(AGENT_TEXT_STREAM_RECORD_STATUS, status, chunkBytes);
  }

  appendProgress(text: string, chunkBytes?: number): void {
    this.appendRecord(AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, text, chunkBytes);
  }

  get hashHex(): string {
    return this.hash.toString("hex");
  }

  get chunkCount(): number {
    return this.count;
  }
}
