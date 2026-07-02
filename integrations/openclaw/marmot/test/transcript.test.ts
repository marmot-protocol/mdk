import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  AgentTextStreamTranscript,
  encodeQuicVarint,
  splitTextDeltas,
} from "../src/transcript.js";

interface TranscriptVector {
  name: string;
  streamIdHex: string;
  startEventIdHex: string;
  chunkBytes: number;
  records: { recordType: number; text: string }[];
  transcriptHashHex: string;
  chunkCount: number;
}

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "vectors", "transcript-vectors.json"), "utf8"),
) as { vectors: TranscriptVector[] };

describe("transcript parity with Rust AgentTextStreamTranscriptV1", () => {
  for (const vector of fixture.vectors) {
    it(`matches Rust hash for: ${vector.name}`, () => {
      const transcript = new AgentTextStreamTranscript(
        Buffer.from(vector.streamIdHex, "hex"),
        Buffer.from(vector.startEventIdHex, "hex"),
      );
      for (const record of vector.records) {
        transcript.appendRecord(record.recordType, record.text, vector.chunkBytes);
      }
      expect(transcript.hashHex).toBe(vector.transcriptHashHex);
      expect(transcript.chunkCount).toBe(vector.chunkCount);
    });
  }
});

describe("encodeQuicVarint", () => {
  it("encodes a 32-byte id length as the single byte 0x20", () => {
    expect([...encodeQuicVarint(32)]).toEqual([0x20]);
  });

  it("encodes boundary values per RFC 9000", () => {
    expect([...encodeQuicVarint(0)]).toEqual([0x00]);
    expect([...encodeQuicVarint(63)]).toEqual([0x3f]);
    expect([...encodeQuicVarint(64)]).toEqual([0x40, 0x40]);
    expect([...encodeQuicVarint(16383)]).toEqual([0x7f, 0xff]);
  });
});

describe("splitTextDeltas", () => {
  it("returns no chunks for empty text", () => {
    expect(splitTextDeltas("", 1024)).toEqual([]);
  });

  it("packs ASCII greedily up to the byte cap", () => {
    expect(splitTextDeltas("hello world", 4).map((c) => c.toString("utf8"))).toEqual([
      "hell",
      "o wo",
      "rld",
    ]);
  });

  it("never splits a multi-byte code point", () => {
    expect(splitTextDeltas("héllo", 2).map((c) => c.toString("utf8"))).toEqual([
      "h",
      "é",
      "ll",
      "o",
    ]);
  });

  it("emits an oversized code point as its own chunk", () => {
    expect(splitTextDeltas("éa", 1).map((c) => c.toString("utf8"))).toEqual(["é", "a"]);
  });

  it("rejects a non-positive chunk size", () => {
    expect(() => splitTextDeltas("x", 0)).toThrow(RangeError);
  });
});
