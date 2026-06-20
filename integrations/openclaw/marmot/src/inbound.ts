// Inbound bridge: holds a long-lived `subscribe_inbound` connection to dm-agent,
// maps inbound Marmot messages to a normalized shape, dedupes by message id, and
// hands each to an injected handler. Reconnects on disconnect; a `resync_required`
// event is surfaced so the caller can re-sync (dm-agent already replays what it
// can before emitting it). SDK-independent so it can be unit-tested directly.

import type { AgentControlEvent, MarmotAgentControlClient } from "./client.js";

export type InboundSubscribeClient = Pick<MarmotAgentControlClient, "subscribeInbound">;

export interface MarmotInboundMessage {
  accountIdHex: string;
  groupIdHex: string;
  messageIdHex: string;
  senderAccountIdHex: string;
  text: string;
}

export interface MarmotGroupInvite {
  accountIdHex: string;
  groupIdHex: string;
}

export interface MarmotInboundBridgeOptions {
  accountIdHex?: string | null;
  groupIdHex?: string | null;
  onReady?: () => void | Promise<void>;
  onMessage: (message: MarmotInboundMessage) => void | Promise<void>;
  /** The agent joined a group via a welcome (used to greet/onboard on join). */
  onGroupInvite?: (invite: MarmotGroupInvite) => void | Promise<void>;
  onResync?: (info: { droppedEvents: number }) => void | Promise<void>;
  onError?: (error: unknown) => void;
  reconnectDelayMs?: number;
  dedupeWindow?: number;
}

const DEFAULT_RECONNECT_DELAY_MS = 1000;
const DEFAULT_DEDUPE_WINDOW = 2048;

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
    const reconnectDelayMs = this.options.reconnectDelayMs ?? DEFAULT_RECONNECT_DELAY_MS;
    while (!signal.aborted) {
      try {
        for await (const event of this.client.subscribeInbound(
          {
            accountIdHex: this.options.accountIdHex ?? null,
            groupIdHex: this.options.groupIdHex ?? null,
          },
          signal,
          { onReady: () => void this.options.onReady?.() },
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
      await delay(reconnectDelayMs, signal);
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
    if (event.type !== "inbound_message") {
      return;
    }
    if (this.recent.has(event.message_id_hex)) {
      return;
    }
    // Record before dispatching: dm-agent can re-emit the same message (e.g. a
    // rapid catch-up just after subscribe), and an agent turn takes long enough
    // that a record-after-dispatch would let the duplicate slip through and
    // start a second, concurrent turn for the same message.
    this.recent.add(event.message_id_hex);
    await this.options.onMessage({
      accountIdHex: event.account_id_hex,
      groupIdHex: event.group_id_hex,
      messageIdHex: event.message_id_hex,
      senderAccountIdHex: event.sender_account_id_hex,
      text: event.text,
    });
  }
}
