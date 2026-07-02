import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  parseAssistantTranscriptLine,
  readLatestAssistantTextFromSessionTranscript,
  resolveLatestAssistantTextFromSessionStore,
} from "../src/session-transcript.js";

describe("session transcript recovery", () => {
  it("extracts the latest visible assistant text from OpenClaw JSONL records", async () => {
    const dir = await mkdtemp(join(tmpdir(), "oc-marmot-transcript-"));
    const transcript = join(dir, "s1.jsonl");
    await writeFile(
      transcript,
      [
        JSON.stringify({
          message: {
            role: "assistant",
            content: [{ type: "text", text: "old answer" }],
            timestamp: 100,
          },
        }),
        JSON.stringify({
          message: {
            role: "assistant",
            provider: "openclaw",
            model: "delivery-mirror",
            content: [{ type: "text", text: "ignore mirror" }],
            timestamp: 110,
          },
        }),
        JSON.stringify({
          message: {
            role: "assistant",
            content: [{ type: "text", text: "new answer" }],
            timestamp: 120,
          },
        }),
      ].join("\n"),
    );

    await expect(readLatestAssistantTextFromSessionTranscript(transcript)).resolves.toEqual({
      text: "new answer",
      timestamp: 120,
    });
  });

  it("prefers final_answer phased text blocks", () => {
    const recovered = parseAssistantTranscriptLine(
      JSON.stringify({
        message: {
          role: "assistant",
          content: [
            { type: "text", text: "thinking", textSignature: JSON.stringify({ phase: "thinking" }) },
            { type: "text", text: "final answer", textSignature: JSON.stringify({ phase: "final_answer" }) },
          ],
        },
      }),
    );
    expect(recovered?.text).toBe("final answer");
  });

  it("resolves a fresh assistant answer through the session store", async () => {
    const dir = await mkdtemp(join(tmpdir(), "oc-marmot-store-"));
    await writeFile(
      join(dir, "sessions.json"),
      JSON.stringify({ "agent:marmot": { sessionId: "s1", sessionFile: "s1.jsonl" } }),
    );
    await writeFile(
      join(dir, "s1.jsonl"),
      `${JSON.stringify({
        message: {
          role: "assistant",
          content: [{ type: "text", text: "fresh answer" }],
          timestamp: 200,
        },
      })}\n`,
    );

    await expect(
      resolveLatestAssistantTextFromSessionStore({
        storePath: join(dir, "sessions.json"),
        sessionKey: "agent:marmot",
        startedAtMs: 150,
      }),
    ).resolves.toBe("fresh answer");
  });

  it("ignores stale assistant answers from before dispatch start", async () => {
    const dir = await mkdtemp(join(tmpdir(), "oc-marmot-store-"));
    await writeFile(join(dir, "sessions.json"), JSON.stringify({ "agent:marmot": { sessionId: "s1" } }));
    await writeFile(
      join(dir, "s1.jsonl"),
      `${JSON.stringify({
        message: {
          role: "assistant",
          content: [{ type: "text", text: "stale answer" }],
          timestamp: 100,
        },
      })}\n`,
    );

    await expect(
      resolveLatestAssistantTextFromSessionStore({
        storePath: join(dir, "sessions.json"),
        sessionKey: "agent:marmot",
        startedAtMs: 150,
      }),
    ).resolves.toBeUndefined();
  });

  it("ignores untimestamped assistant answers during dispatch recovery", async () => {
    const dir = await mkdtemp(join(tmpdir(), "oc-marmot-store-"));
    await writeFile(join(dir, "sessions.json"), JSON.stringify({ "agent:marmot": { sessionId: "s1" } }));
    await writeFile(
      join(dir, "s1.jsonl"),
      `${JSON.stringify({
        message: {
          role: "assistant",
          content: [{ type: "text", text: "unknown freshness" }],
        },
      })}\n`,
    );

    await expect(
      resolveLatestAssistantTextFromSessionStore({
        storePath: join(dir, "sessions.json"),
        sessionKey: "agent:marmot",
        startedAtMs: 150,
      }),
    ).resolves.toBeUndefined();
  });
});
