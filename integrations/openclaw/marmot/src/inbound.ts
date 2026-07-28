// Inbound bridge: holds a long-lived `subscribe_inbound` connection to wn-agent,
// maps inbound Marmot messages to a normalized shape, dedupes by message id, and
// hands each to an injected handler. Reconnects on disconnect; a `resync_required`
// event is surfaced so the caller can re-sync (wn-agent already replays what it
// can before emitting it). SDK-independent so it can be unit-tested directly.

import type {
  AgentControlActor,
  AgentControlReferencedMessage,
  AgentControlEvent,
  AgentControlMediaRef,
  MarmotAgentControlClient,
} from "./client.js";

export type InboundSubscribeClient = Pick<MarmotAgentControlClient, "subscribeInbound">;

export interface MarmotInboundMessage {
  accountIdHex: string;
  groupIdHex: string;
  messageIdHex: string;
  senderAccountIdHex: string;
  sender?: AgentControlActor;
  text: string;
  /** Sender-authenticated event time in Unix seconds. */
  recordedAt?: number;
  /**
   * True when the message addresses the agent via p-tag, nostr hex, or visible
   * npub mention.
   */
  mentionsSelf?: boolean;
  /** The message id this message replies to, when present. */
  replyToMessageIdHex?: string | null;
  /** Bounded, privacy-aware reply snapshot from wn-agent. */
  replyTo?: AgentControlReferencedMessage | null;
  /** Sender's directory display name, when resolvable. */
  senderDisplayName?: string | null;
  /** Encrypted media references (`imeta` tags) attached to this message, if any. */
  media?: AgentControlMediaRef[];
  /** Structured, untrusted facts buffered since the previous triggering turn. */
  ambientContext?: MarmotAmbientEvent[];
}

export interface MarmotGroupInvite {
  accountIdHex: string;
  groupIdHex: string;
}

export interface MarmotGroupStateChanged {
  accountIdHex: string;
  groupIdHex: string;
  /**
   * Coarse change kind: "member_added" | "member_removed" | "member_left" |
   * "admin_added" | "admin_removed" | "group_renamed" | "group_avatar_changed" |
   * "disappearing_timer_changed".
   * Privacy: never carries a member pubkey.
   */
  change: string;
  /** New group display name for "group_renamed"; absent otherwise. */
  detail?: string | null;
}

export type MarmotMutationEvent = Extract<
  AgentControlEvent,
  {
    type:
      | "message_edited"
      | "message_deleted"
      | "reaction_added"
      | "reaction_removed";
  }
>;

export type MarmotAmbientEvent = MarmotMutationEvent | {
  type: "group_state_changed";
  account_id_hex: string;
  group_id_hex: string;
  change: string;
  detail?: string | null;
};

export interface MarmotInboundBridgeOptions {
  accountIdHex?: string | null;
  groupIdHex?: string | null;
  onReady?: () => void | Promise<void>;
  onMessage: (message: MarmotInboundMessage) => void | Promise<void>;
  /** The agent joined a group via a welcome (used to greet/onboard on join). */
  onGroupInvite?: (invite: MarmotGroupInvite) => void | Promise<void>;
  /** A durable mutation/group-state fact that must not trigger a turn. */
  onAmbientEvent?: (event: MarmotAmbientEvent) => void | Promise<void>;
  onResync?: (info: { droppedEvents: number }) => void | Promise<void>;
  onError?: (error: unknown) => void;
  /** Base reconnect delay (first attempt). Grows exponentially up to the cap. */
  reconnectDelayMs?: number;
  /** Cap on the reconnect delay after exponential growth. */
  maxReconnectDelayMs?: number;
  dedupeWindow?: number;
}

const DEFAULT_RECONNECT_DELAY_MS = 1000;
const DEFAULT_MAX_RECONNECT_DELAY_MS = 30_000;
const DEFAULT_DEDUPE_WINDOW = 2048;

/**
 * Reconnect backoff with jitter: a delay in `[baseMs, min(capMs, baseMs * 2**attempt)]`.
 * Attempt 0 returns exactly `baseMs` (ceiling == base), so the first reconnect is as
 * prompt as the old flat delay; later attempts grow geometrically toward `capMs`. The
 * jitter spreads retries so a persistent failure (e.g. wn-agent down) doesn't spin at a
 * fixed cadence competing for the event loop the rest of the gateway shares.
 */
export function reconnectBackoffMs(
  attempt: number,
  baseMs: number,
  capMs: number,
  rand: () => number = Math.random,
): number {
  if (baseMs <= 0) {
    return 0;
  }
  const ceiling = Math.min(capMs, baseMs * 2 ** Math.max(0, attempt));
  if (ceiling <= baseMs) {
    return baseMs;
  }
  return Math.round(baseMs + rand() * (ceiling - baseMs));
}

/** Bounded insertion-ordered set for recent message-id dedupe. */
class RecentIds {
  private readonly ids = new Set<string>();
  constructor(private readonly max: number) {}

  has(id: string): boolean {
    return this.ids.has(id);
  }

  add(id: string): void {
    this.ids.add(id);
    if (this.ids.size > this.max) {
      const oldest = this.ids.values().next().value;
      if (oldest !== undefined) {
        this.ids.delete(oldest);
      }
    }
  }
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  if (ms <= 0 || signal.aborted) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export class MarmotInboundBridge {
  private readonly recent: RecentIds;

  constructor(
    private readonly client: InboundSubscribeClient,
    private readonly options: MarmotInboundBridgeOptions,
  ) {
    this.recent = new RecentIds(options.dedupeWindow ?? DEFAULT_DEDUPE_WINDOW);
  }

  /** Run until `signal` aborts, reconnecting between subscription drops. */
  async run(signal: AbortSignal): Promise<void> {
    const baseDelayMs = this.options.reconnectDelayMs ?? DEFAULT_RECONNECT_DELAY_MS;
    const maxDelayMs = this.options.maxReconnectDelayMs ?? DEFAULT_MAX_RECONNECT_DELAY_MS;
    // `reconnectBackoffMs` returns `baseMs` whenever the ceiling collapses to it,
    // so a configured cap below the base would otherwise be exceeded. Clamp the
    // base to the cap so the delay never goes above the cap.
    const effectiveBaseMs = Math.min(baseDelayMs, maxDelayMs);
    // Consecutive reconnect attempts that have not (re)established a subscription.
    // Reset to 0 once a subscription is acked (onReady) so a healthy connection
    // always reconnects promptly, while a persistent failure backs off geometrically
    // instead of spinning at a flat 1/s.
    let attempt = 0;
    while (!signal.aborted) {
      try {
        for await (const event of this.client.subscribeInbound(
          {
            accountIdHex: this.options.accountIdHex ?? null,
            groupIdHex: this.options.groupIdHex ?? null,
          },
          signal,
          {
            onReady: () => {
              attempt = 0;
              Promise.resolve(this.options.onReady?.()).catch((err) => {
                this.options.onError?.(err);
              });
            },
          },
        )) {
          if (signal.aborted) {
            return;
          }
          await this.handle(event);
        }
      } catch (error) {
        // An abort tears down the socket, which surfaces here as a read error;
        // that is expected shutdown, not a fault.
        if (!signal.aborted) {
          this.options.onError?.(error);
        }
      }
      if (signal.aborted) {
        return;
      }
      await delay(reconnectBackoffMs(attempt, effectiveBaseMs, maxDelayMs), signal);
      attempt += 1;
    }
  }

  private async handle(event: AgentControlEvent): Promise<void> {
    if (event.type === "resync_required") {
      await this.options.onResync?.({ droppedEvents: event.dropped_events });
      return;
    }
    if (event.type === "group_invite") {
      await this.options.onGroupInvite?.({
        accountIdHex: event.account_id_hex,
        groupIdHex: event.group_id_hex,
      });
      return;
    }
    if (
      event.type === "message_edited" ||
      event.type === "message_deleted" ||
      event.type === "reaction_added" ||
      event.type === "reaction_removed"
    ) {
      if (this.recent.has(event.event_id_hex)) {
        return;
      }
      this.recent.add(event.event_id_hex);
      await this.options.onAmbientEvent?.(event);
      return;
    }
    if (event.type === "group_state_changed") {
      await this.options.onAmbientEvent?.(event);
      return;
    }
    if (event.type !== "inbound_message") {
      return;
    }
    if (this.recent.has(event.message.message_id_hex)) {
      return;
    }
    // Record before dispatching: wn-agent can re-emit the same message (e.g. a
    // rapid catch-up just after subscribe), and an agent turn takes long enough
    // that a record-after-dispatch would let the duplicate slip through and
    // start a second, concurrent turn for the same message.
    this.recent.add(event.message.message_id_hex);
    await this.options.onMessage({
      accountIdHex: event.account_id_hex,
      groupIdHex: event.group_id_hex,
      messageIdHex: event.message.message_id_hex,
      senderAccountIdHex: event.message.sender.account_id_hex,
      sender: event.message.sender,
      text: event.message.text,
      recordedAt: event.message.recorded_at,
      mentionsSelf: event.mentions_self ?? false,
      replyToMessageIdHex: event.reply_to?.message_id_hex ?? null,
      replyTo: event.reply_to ?? null,
      senderDisplayName: event.message.sender.display_name ?? null,
      media: event.message.media ?? [],
    });
  }
}
