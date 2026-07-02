// Public Nostr profile (kind:0) name flow for the Marmot agent. The agent asks
// once, on its own, when it joins a group: it offers to publish a public profile
// name and the user chooses whether to (that choice is the consent — there is no
// config opt-in). If the OpenClaw agent has a configured name it is offered as
// the default ("reply yes, a different name, or skip"); otherwise the user is
// asked to supply a name. Per-account status is persisted so it never re-asks.
//
// Privacy: never log names, account ids, or group ids — only generic lifecycle
// messages. The 0600 state file holds names/group ids by necessity; that is local
// state, not logging.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export const MAX_PROFILE_NAME_CHARS = 80;

export const PROFILE_PROMPT_WITH_NAME =
  "Hi! I can publish a public Nostr profile so I show up with a name. Want me to " +
  'publish it as "{name}"? Reply "yes" to use that, reply with a different name to ' +
  'use instead, or reply "skip" to stay unnamed.';
export const PROFILE_PROMPT_NO_NAME =
  "Hi! I can publish a public Nostr profile so I show up with a name. Reply with a " +
  'name to publish, or reply "skip" to stay unnamed.';
export const PROFILE_NAME_PUBLISHED =
  'Done. I published this agent\'s public Nostr profile name as "{name}".';
export const PROFILE_NAME_SKIPPED = "Okay, I will stay unnamed for now.";
export const PROFILE_NAME_EMPTY = 'Please reply with a name, or reply "skip" to stay unnamed.';
export const PROFILE_NAME_TOO_LONG =
  'That name is too long. Please reply with a shorter name, or reply "skip" to stay unnamed.';
export const PROFILE_NAME_PUBLISH_FAILED =
  "I could not publish that profile name yet. Please try again later.";

const PROFILE_NAME_SKIP_REPLIES = new Set(["/skip", "cancel", "no", "no thanks", "not now", "skip"]);
const PROFILE_NAME_AFFIRM_REPLIES = new Set([
  "yes",
  "y",
  "yeah",
  "yep",
  "yup",
  "sure",
  "ok",
  "okay",
  "publish",
  "publish it",
  "do it",
  "go ahead",
]);

/** Collapse runs of whitespace and trim, matching Hermes' " ".join(text.split()). */
function normalizeWhitespace(text: string): string {
  return String(text ?? "")
    .split(/\s+/)
    .filter((part) => part.length > 0)
    .join(" ");
}

/** A validated configured name, or undefined when missing/too long. */
export function validProfileName(name: string | null | undefined): string | undefined {
  const trimmed = normalizeWhitespace(String(name ?? ""));
  if (!trimmed || trimmed.length > MAX_PROFILE_NAME_CHARS) {
    return undefined;
  }
  return trimmed;
}

/** The proactive prompt text, offering the configured name as the default if present. */
export function buildProfilePrompt(suggestedName: string | undefined): string {
  return suggestedName
    ? PROFILE_PROMPT_WITH_NAME.replace("{name}", suggestedName)
    : PROFILE_PROMPT_NO_NAME;
}

export type ProfileNameReply =
  | { action: "skip"; response: string }
  | { action: "affirm"; response: string }
  | { action: "invalid"; response: string }
  | { action: "name"; name: string; response: string };

/** Interpret a user's reply to the profile-name prompt. */
export function parseProfileNameReply(text: string): ProfileNameReply {
  let value = normalizeWhitespace(text);
  if (!value) {
    return { action: "invalid", response: PROFILE_NAME_EMPTY };
  }
  const lowered = value.toLowerCase();
  if (PROFILE_NAME_SKIP_REPLIES.has(lowered)) {
    return { action: "skip", response: PROFILE_NAME_SKIPPED };
  }
  if (PROFILE_NAME_AFFIRM_REPLIES.has(lowered)) {
    return { action: "affirm", response: "" };
  }
  // Strip a single pair of surrounding matching quotes.
  const first = value[0];
  if (value.length >= 2 && first === value[value.length - 1] && (first === "'" || first === '"')) {
    value = normalizeWhitespace(value.slice(1, -1));
  }
  if (!value) {
    return { action: "invalid", response: PROFILE_NAME_EMPTY };
  }
  if (value.length > MAX_PROFILE_NAME_CHARS) {
    return { action: "invalid", response: PROFILE_NAME_TOO_LONG };
  }
  return { action: "name", name: value, response: "" };
}

// --- persisted per-account status ------------------------------------------

export type OnboardingStatus = "prompted" | "published" | "skipped";

export interface OnboardingRecord {
  status: OnboardingStatus;
  group_id_hex?: string;
  name?: string;
  suggested_name?: string;
}

/** State store interface (the runtime uses the file-backed impl; tests stub it). */
export interface ProfileOnboardingStateStore {
  get(accountIdHex: string): Promise<Partial<OnboardingRecord>>;
  /** Atomically claim the one-time prompt slot. Returns true if the caller should send. */
  tryClaimPrompt(
    accountIdHex: string,
    groupIdHex: string,
    suggestedName: string | undefined,
  ): Promise<boolean>;
  markPublished(accountIdHex: string, name: string): Promise<void>;
  markSkipped(accountIdHex: string): Promise<void>;
  /** Reset an account's record (used to retry after a prompt send fails). */
  clear(accountIdHex: string): Promise<void>;
}

interface StoreFile {
  marmot_profile_onboarding: "v1";
  accounts: Record<string, OnboardingRecord>;
}

/**
 * Tiny local JSON state file (0600) recording the one-time consent flow per
 * account. Writes are atomic (tmp + rename) and serialized in-process so the
 * join trigger and a racing first message cannot double-claim the prompt slot.
 */
export class ProfileNameOnboardingStore implements ProfileOnboardingStateStore {
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly path: string) {}

  private serialize<T>(op: () => Promise<T>): Promise<T> {
    const next = this.chain.then(op, op);
    this.chain = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private async load(): Promise<StoreFile> {
    try {
      const data = JSON.parse(await readFile(this.path, "utf8")) as Partial<StoreFile>;
      const accounts =
        data && typeof data === "object" && data.accounts && typeof data.accounts === "object"
          ? (data.accounts as Record<string, OnboardingRecord>)
          : {};
      return { marmot_profile_onboarding: "v1", accounts };
    } catch {
      return { marmot_profile_onboarding: "v1", accounts: {} };
    }
  }

  private async persist(data: StoreFile): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, `${JSON.stringify(data)}\n`, { mode: 0o600 });
    await rename(tmp, this.path);
  }

  get(accountIdHex: string): Promise<Partial<OnboardingRecord>> {
    return this.serialize(async () => {
      const data = await this.load();
      return { ...(data.accounts[accountIdHex] ?? {}) };
    });
  }

  tryClaimPrompt(
    accountIdHex: string,
    groupIdHex: string,
    suggestedName: string | undefined,
  ): Promise<boolean> {
    return this.serialize(async () => {
      const data = await this.load();
      if (data.accounts[accountIdHex]?.status) {
        return false;
      }
      data.accounts[accountIdHex] = {
        status: "prompted",
        group_id_hex: groupIdHex,
        ...(suggestedName ? { suggested_name: suggestedName } : {}),
      };
      await this.persist(data);
      return true;
    });
  }

  private set(accountIdHex: string, record: OnboardingRecord): Promise<void> {
    return this.serialize(async () => {
      const data = await this.load();
      data.accounts[accountIdHex] = record;
      await this.persist(data);
    });
  }

  markPublished(accountIdHex: string, name: string): Promise<void> {
    return this.set(accountIdHex, { status: "published", name });
  }

  markSkipped(accountIdHex: string): Promise<void> {
    return this.set(accountIdHex, { status: "skipped" });
  }

  clear(accountIdHex: string): Promise<void> {
    return this.serialize(async () => {
      const data = await this.load();
      delete data.accounts[accountIdHex];
      await this.persist(data);
    });
  }
}

// --- the runtime entry points ------------------------------------------------

export interface ProfileOnboardingClient {
  sendFinal(
    accountIdHex: string,
    groupIdHex: string,
    text: string,
    replyToMessageIdHex?: string | null,
  ): Promise<unknown>;
  accountPublishProfile(
    accountIdHex: string,
    name: string,
    displayName?: string | null,
  ): Promise<unknown>;
}

interface OnboardingLogger {
  info?: (message: string) => void;
  warn?: (message: string) => void;
}

/**
 * Send the one-time profile prompt for an account, claiming the prompt slot
 * atomically first so a join event and a racing first message can't double-ask.
 * No-op once any status (prompted/published/skipped) exists.
 */
async function sendProfilePrompt(deps: {
  store: ProfileOnboardingStateStore;
  client: ProfileOnboardingClient;
  accountIdHex: string;
  groupIdHex: string;
  configuredName?: string | null;
  logger?: OnboardingLogger;
}): Promise<void> {
  const suggested = validProfileName(deps.configuredName);
  const claimed = await deps.store.tryClaimPrompt(deps.accountIdHex, deps.groupIdHex, suggested);
  if (!claimed) {
    return;
  }
  try {
    await deps.client.sendFinal(deps.accountIdHex, deps.groupIdHex, buildProfilePrompt(suggested));
    deps.logger?.info?.("marmot: profile onboarding prompt sent");
  } catch {
    // Could not deliver the prompt; release the slot so a later trigger retries.
    await deps.store.clear(deps.accountIdHex).catch(() => undefined);
    deps.logger?.warn?.("marmot: failed to send profile onboarding prompt");
  }
}

/** Send the proactive prompt when the agent joins a group (group_invite). */
export function maybeSendProfilePromptOnJoin(deps: {
  store: ProfileOnboardingStateStore;
  client: ProfileOnboardingClient;
  accountIdHex: string;
  groupIdHex: string;
  configuredName?: string | null;
  logger?: OnboardingLogger;
}): Promise<void> {
  return sendProfilePrompt(deps);
}

export interface ProfileOnboardingMessage {
  accountIdHex: string;
  groupIdHex: string;
  messageIdHex: string;
  text: string;
}

async function publishAndConfirm(
  store: ProfileOnboardingStateStore,
  client: ProfileOnboardingClient,
  message: ProfileOnboardingMessage,
  name: string,
  logger?: OnboardingLogger,
): Promise<void> {
  try {
    await client.accountPublishProfile(message.accountIdHex, name, name);
    await store.markPublished(message.accountIdHex, name);
    await client.sendFinal(
      message.accountIdHex,
      message.groupIdHex,
      PROFILE_NAME_PUBLISHED.replace("{name}", name),
      message.messageIdHex,
    );
    logger?.info?.("marmot: profile name published");
  } catch {
    await client.sendFinal(
      message.accountIdHex,
      message.groupIdHex,
      PROFILE_NAME_PUBLISH_FAILED,
      message.messageIdHex,
    );
    logger?.warn?.("marmot: profile name publish failed");
  }
}

/**
 * Handle an inbound message against the onboarding flow. Returns true when the
 * message was consumed (skip the normal agent turn): either it answered an open
 * prompt, or — for a group the agent joined before this ran (no join event) — it
 * triggered the prompt as a fallback.
 */
export async function maybeHandleProfileOnboardingInbound(deps: {
  store: ProfileOnboardingStateStore;
  client: ProfileOnboardingClient;
  message: ProfileOnboardingMessage;
  configuredName?: string | null;
  logger?: OnboardingLogger;
}): Promise<boolean> {
  const { store, client, message, logger } = deps;
  const record = await store.get(message.accountIdHex);

  if (record.status === "published" || record.status === "skipped") {
    return false;
  }

  if (record.status === "prompted") {
    if (record.group_id_hex !== message.groupIdHex) {
      return false; // the prompt is awaiting a reply in a different conversation
    }
    const parsed = parseProfileNameReply(message.text);
    if (parsed.action === "skip") {
      await store.markSkipped(message.accountIdHex);
      await client.sendFinal(message.accountIdHex, message.groupIdHex, parsed.response, message.messageIdHex);
      logger?.info?.("marmot: profile onboarding skipped");
      return true;
    }
    if (parsed.action === "affirm") {
      const suggested = validProfileName(record.suggested_name);
      if (suggested) {
        await publishAndConfirm(store, client, message, suggested, logger);
      } else {
        await client.sendFinal(message.accountIdHex, message.groupIdHex, PROFILE_NAME_EMPTY, message.messageIdHex);
      }
      return true;
    }
    if (parsed.action === "invalid") {
      await client.sendFinal(message.accountIdHex, message.groupIdHex, parsed.response, message.messageIdHex);
      return true; // stay prompted; the prompt is implicitly re-asked
    }
    await publishAndConfirm(store, client, message, parsed.name, logger);
    return true;
  }

  // No status yet: the agent is already in this group (no join event replayed),
  // so fall back to prompting now and consume this message.
  await sendProfilePrompt({
    store,
    client,
    accountIdHex: message.accountIdHex,
    groupIdHex: message.groupIdHex,
    configuredName: deps.configuredName,
    logger,
  });
  return true;
}
