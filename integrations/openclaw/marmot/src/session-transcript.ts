// Best-effort OpenClaw session transcript reader used only to recover the full
// final assistant text when a channel streaming mode delivered a truncated or
// windowed preview to our reply sink.

import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";

export interface LatestAssistantText {
  text: string;
  timestamp?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isTranscriptOnlyOpenClawAssistant(message: Record<string, unknown>): boolean {
  return (
    message.provider === "openclaw" &&
    typeof message.model === "string" &&
    (message.model === "delivery-mirror" || message.model === "gateway-injected")
  );
}

function textPhase(value: unknown): string | undefined {
  if (typeof value !== "string" || value.trim().length === 0) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    if (isRecord(parsed) && typeof parsed.phase === "string") {
      return parsed.phase;
    }
  } catch {
    // Older signatures are plain strings; treat those as unphased.
  }
  return undefined;
}

function extractAssistantVisibleText(message: Record<string, unknown>): string | undefined {
  const phase = typeof message.phase === "string" ? message.phase : undefined;
  const shouldInclude = (resolved: string | undefined, requested?: string) =>
    requested ? resolved === requested : resolved === undefined;
  const readDirectText = (value: unknown, requested?: string) => {
    if (typeof value !== "string" || !shouldInclude(phase, requested)) {
      return undefined;
    }
    return value.trim() || undefined;
  };

  const directFinal = readDirectText(message.text ?? message.content, "final_answer");
  if (directFinal) {
    return directFinal;
  }
  const directPlain = readDirectText(message.text ?? message.content);
  if (directPlain) {
    return directPlain;
  }

  const content = message.content;
  if (!Array.isArray(content)) {
    return undefined;
  }

  const hasExplicitPhases = content.some(
    (block) => isRecord(block) && block.type === "text" && textPhase(block.textSignature) !== undefined,
  );

  const collect = (requested?: string) =>
    content
      .map((block) => {
        if (!isRecord(block) || block.type !== "text" || typeof block.text !== "string") {
          return null;
        }
        const blockPhase = textPhase(block.textSignature) ?? (hasExplicitPhases ? undefined : phase);
        if (!shouldInclude(blockPhase, requested)) {
          return null;
        }
        const text = block.text.trim();
        return text.length > 0 ? text : null;
      })
      .filter((value): value is string => typeof value === "string");

  const finalParts = collect("final_answer");
  if (finalParts.length > 0) {
    return finalParts.join("\n").trim() || undefined;
  }
  if (hasExplicitPhases) {
    return undefined;
  }
  const plainParts = collect();
  return plainParts.length > 0 ? plainParts.join("\n").trim() || undefined : undefined;
}

export function parseAssistantTranscriptLine(line: string): LatestAssistantText | undefined {
  const parsed = JSON.parse(line) as unknown;
  if (!isRecord(parsed) || !isRecord(parsed.message)) {
    return undefined;
  }
  const message = parsed.message;
  if (message.role !== "assistant" || isTranscriptOnlyOpenClawAssistant(message)) {
    return undefined;
  }
  const text = extractAssistantVisibleText(message);
  if (!text) {
    return undefined;
  }
  const timestamp = typeof message.timestamp === "number" && Number.isFinite(message.timestamp)
    ? message.timestamp
    : undefined;
  return { text, ...(timestamp !== undefined ? { timestamp } : {}) };
}

export async function readLatestAssistantTextFromSessionTranscript(
  sessionFile: string | undefined,
): Promise<LatestAssistantText | undefined> {
  if (!sessionFile?.trim()) {
    return undefined;
  }
  let content: string;
  try {
    content = await readFile(sessionFile, "utf8");
  } catch {
    return undefined;
  }
  const lines = content.split(/\r?\n/);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index]?.trim();
    if (!line) {
      continue;
    }
    try {
      const latest = parseAssistantTranscriptLine(line);
      if (latest) {
        return latest;
      }
    } catch {
      continue;
    }
  }
  return undefined;
}

function sessionStoreEntry(store: unknown, sessionKey: string): Record<string, unknown> | undefined {
  if (!isRecord(store)) {
    return undefined;
  }
  const exact = store[sessionKey];
  if (isRecord(exact)) {
    return exact;
  }
  const folded = store[sessionKey.toLowerCase()];
  return isRecord(folded) ? folded : undefined;
}

function resolveSessionFile(storePath: string, entry: Record<string, unknown>): string | undefined {
  const baseDir = dirname(resolve(storePath));
  if (typeof entry.sessionFile === "string" && entry.sessionFile.trim().length > 0) {
    const candidate = entry.sessionFile.trim();
    return isAbsolute(candidate) ? candidate : resolve(baseDir, candidate);
  }
  if (typeof entry.sessionId === "string" && /^[a-z0-9][a-z0-9._-]{0,127}$/i.test(entry.sessionId)) {
    return join(baseDir, `${entry.sessionId}.jsonl`);
  }
  return undefined;
}

export async function resolveLatestAssistantTextFromSessionStore(params: {
  storePath: string;
  sessionKey: string;
  startedAtMs: number;
}): Promise<string | undefined> {
  let raw: string;
  try {
    raw = await readFile(params.storePath, "utf8");
  } catch {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const entry = sessionStoreEntry(parsed, params.sessionKey);
  if (!entry) {
    return undefined;
  }
  const latest = await readLatestAssistantTextFromSessionTranscript(
    resolveSessionFile(params.storePath, entry),
  );
  if (!latest) {
    return undefined;
  }
  if (!latest.timestamp || latest.timestamp < params.startedAtMs) {
    return undefined;
  }
  return latest.text;
}
