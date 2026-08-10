// Inbound runtime wiring + startup allowlist sync.
//
// `startMarmotInbound` runs the wn-agent inbound subscription and hands each
// mapped message to a real agent dispatcher (no production no-op fallback —
// consuming inbound without dispatching would silently swallow messages). The
// dispatcher in `src/dispatch.ts` drives the OpenClaw turn kernel; the channel's
// `gateway.startAccount` task owns this runtime for its full lifetime.
//
// `syncMarmotAllowlist` mirrors the configured `dm.allowFrom` welcomers into
// wn-agent's per-account allowlist so configured welcomers are accepted.

import { createInboundDebouncer } from "openclaw/plugin-sdk/channel-inbound-debounce";
import type { ChannelAccountSnapshot } from "openclaw/plugin-sdk/status-helpers";

import { resolveSingleAccount } from "./account.js";
import { BoundedKeyedAsyncQueue, DEFAULT_INBOUND_QUEUE_MAX_DEPTH } from "./bounded-keyed-async-queue.js";
import { resolveMarmotChannelAccount } from "./channel.js";
import type { MarmotAgentControlClient } from "./client.js";
import { clientForAccount, type ResolvedMarmotAccount } from "./config.js";
import {
  MarmotInboundBridge,
  type MarmotAmbientEvent,
  type MarmotInboundMessage,
} from "./inbound.js";
import {
  maybeHandleProfileOnboardingInbound,
  maybeSendProfilePromptOnJoin,
  ProfileNameOnboardingStore,
} from "./profile-onboarding.js";
import {
  DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
  markMarmotInboundReady,
  markMarmotInboundReceived,
  markMarmotInboundReconnect,
  markMarmotInboundStarting,
  markMarmotInboundStopped,
} from "./runtime-state.js";
import { syncAllowlist } from "./security.js";

/**
 * OpenClaw stable awaits an onFlush Promise directly. 2026.7.2-beta instead
 * supplies a createFlush factory and expects admission + completion promises.
 * Keep the adapter structural so the packaged stable build can run on either
 * host without importing a beta-only type or branching on a version string.
 */
interface CompatibleInboundDebounceFlush {
  admission: Promise<void>;
  completion: Promise<void>;
}

type CompatibleInboundDebounceFlushFactory = (params: {
  dispatch: (lifecycle: unknown) => Promise<void>;
}) => CompatibleInboundDebounceFlush;

type CompatibleInboundDebouncerFactory = <T>(params: {
  debounceMs: number;
  buildKey: (item: T) => string | null | undefined;
  onFlush: (
    items: T[],
    createFlush?: CompatibleInboundDebounceFlushFactory,
  ) => Promise<void> | CompatibleInboundDebounceFlush;
}) => {
  enqueue: (item: T) => Promise<void>;
};

const createCompatibleInboundDebouncer =
  createInboundDebouncer as unknown as CompatibleInboundDebouncerFactory;

/** Minimal logger surface (subset of OpenClaw's PluginLogger). */
interface InboundLogger {
  info: (message: string) => void;
  warn: (message: string) => void;
}

/** Minimal plugin-api surface used by the inbound runtime. */
export interface InboundPluginApi {
  /** Full OpenClaw config; the channel config lives at `channels.marmot`. */
  config: unknown;
  logger: InboundLogger;
}

type ClientFactory = (resolved: ResolvedMarmotAccount) => MarmotAgentControlClient;
const MAX_PENDING_AMBIENT_EVENTS_PER_GROUP = 16;
const MAX_PENDING_AMBIENT_GROUPS = 256;

function resolveAccount(
  api: InboundPluginApi,
  channelAccountId?: string | null,
): ResolvedMarmotAccount {
  return resolveMarmotChannelAccount(
    api.config as Parameters<typeof resolveMarmotChannelAccount>[0],
    channelAccountId ?? null,
  );
}

/**
 * Map a coarse group-state change kind to a short, privacy-safe sentence for
 * ambient agent context. NEVER includes a member pubkey; the only detail
 * surfaced is the new group name on a rename (already non-secret group metadata).
 */
/**
 * Merge a debounce batch of same-key inbound messages into one turn.
 *
 * The newest message remains the representative for ids/display metadata, while
 * turn-signaling fields that can appear on any burst member are merged so a
 * non-last image, mention, or reply does not disappear during debounce.
 */
function coalesceInboundMessages(items: MarmotInboundMessage[]): MarmotInboundMessage {
  const last = items[items.length - 1]!;
  if (items.length === 1) {
    return last;
  }
  const text = items
    .map((item) => item.text)
    .filter((part) => part.length > 0)
    .join("\n");
  const media: NonNullable<MarmotInboundMessage["media"]> = [];
  const mediaHashes = new Set<string>();
  for (const item of items) {
    for (const ref of item.media ?? []) {
      if (!mediaHashes.has(ref.ciphertext_sha256)) {
        mediaHashes.add(ref.ciphertext_sha256);
        media.push(ref);
      }
    }
  }
  const replyToMessageIdHex =
    items
      .toReversed()
      .find((item) => item.replyToMessageIdHex)?.replyToMessageIdHex ?? null;
  return {
    ...last,
    text,
    mentionsSelf: items.some((item) => item.mentionsSelf === true),
    replyToMessageIdHex,
    replyTo:
      items
        .toReversed()
        .find((item) => item.replyTo)?.replyTo ?? null,
    media,
    ambientContext: items.flatMap((item) => item.ambientContext ?? []),
  };
}

export type InboundAgentDispatcher = (
  message: MarmotInboundMessage,
) => boolean | void | Promise<boolean | void>;

/**
 * A passive ambient event surfaced to the agent as next-turn context (no reply
 * is triggered). `groupIdHex` selects the agent session; `text` is a short,
 * privacy-safe sentence; `contextKey` dedupes repeated surfacings of the same
 * fact. Built in `index.ts` over the full plugin api (it needs
 * `api.runtime.system`/`api.runtime.channel`, which the narrowed
 * `InboundPluginApi` does not expose) and passed in here.
 */
export interface StartMarmotInboundOptions {
  signal?: AbortSignal;
  /** OpenClaw channel account id that owns this subscription. */
  channelAccountId?: string | null;
  /** Gateway-owned status writer. */
  statusSink?: (patch: Partial<ChannelAccountSnapshot>) => void;
  /** Override the control-client factory (tests inject a stub). */
  clientFactory?: ClientFactory;
  /**
   * Configured OpenClaw agent name. When profile-name onboarding is enabled and
   * a name is present, it is inherited and published instead of asking in-chat.
   */
  configuredAgentName?: string | null;
  /**
   * Invalidate the dispatcher's cached `is_direct` activation fact for one group.
   * Called when wn-agent reports a `group_state_changed` event so the next
   * unaddressed message in that group re-reads fresh membership instead of a
   * stale cached value. When omitted, the cache is never invalidated from here.
   */
  invalidateGroupActivation?: (accountIdHex: string, groupIdHex: string) => void;
  /**
   * Drop every cached `is_direct` activation fact. Called on an inbound resync,
   * where dropped broadcast slots mean a `group_state_changed` for some group may
   * have been missed, so no cached membership can be trusted.
   */
  clearGroupActivationCache?: () => void;
}

// OpenClaw owns one gateway task per configured channel account. Keep one
// subscription per account even if a host accidentally starts the same task
// twice.
const inboundActiveAccounts = new Set<string>();

export function resetMarmotInboundAccountsForTests(): void {
  inboundActiveAccounts.clear();
}

/**
 * Run the wn-agent inbound subscription, dispatching each mapped message to
 * `dispatch`. Returns a stop function that aborts the loop. Requires a real
 * dispatcher — see the module note.
 */
export function startMarmotInbound(
  api: InboundPluginApi,
  dispatch: InboundAgentDispatcher,
  options: StartMarmotInboundOptions = {},
): () => void {
  const resolved = resolveAccount(api, options.channelAccountId);
  const inboundAccountKey =
    options.channelAccountId?.trim() ||
    resolved.accountId ||
    DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
  if (inboundActiveAccounts.has(inboundAccountKey)) {
    api.logger.info("marmot: inbound subscription already active; ignoring duplicate start");
    return () => {};
  }
  const statusAccountId = resolved.accountId ?? inboundAccountKey;
  inboundActiveAccounts.add(inboundAccountKey);
  markMarmotInboundStarting(statusAccountId);
  options.statusSink?.({
    running: true,
    connected: false,
    lastStartAt: Date.now(),
    lastStopAt: null,
    lastError: null,
  });
  const controller = new AbortController();
  // Release the guard when the loop is stopped so a clean restart can re-subscribe.
  controller.signal.addEventListener(
    "abort",
    () => {
      inboundActiveAccounts.delete(inboundAccountKey);
      markMarmotInboundStopped(statusAccountId);
      options.statusSink?.({
        running: false,
        connected: false,
        lastStopAt: Date.now(),
      });
    },
    { once: true },
  );
  // Always drive the loop off the internal controller so the returned stop() is
  // authoritative; forward an externally-supplied signal into it.
  if (options.signal) {
    if (options.signal.aborted) {
      controller.abort();
    } else {
      options.signal.addEventListener("abort", () => controller.abort(), { once: true });
    }
  }
  const signal = controller.signal;
  const client = (options.clientFactory ?? clientForAccount)(resolved);
  // One-time, opt-in public profile-name flow (default off). Runs ahead of the
  // agent turn so a consent prompt/reply isn't fed to the model.
  const onboardingStore = resolved.profileNameOnboarding
    ? new ProfileNameOnboardingStore(resolved.profileOnboardingStatePath)
    : null;

  void (async () => {
    let accountIdHex: string;
    try {
      accountIdHex = resolved.marmotAccountIdHex ?? (await resolveSingleAccount(client));
    } catch {
      api.logger.warn("marmot: could not resolve an agent account for the inbound subscription");
      inboundActiveAccounts.delete(inboundAccountKey);
      markMarmotInboundStopped(statusAccountId);
      options.statusSink?.({
        running: false,
        connected: false,
        lastStopAt: Date.now(),
        lastError: "could not resolve agent account",
      });
      return;
    }
    let readyLogged = false;
    const pendingAmbient = new Map<string, MarmotAmbientEvent[]>();
    const ambientKey = (account: string, group: string) => `${account}:${group}`;
    const ensurePendingAmbientGroupCapacity = (key: string): void => {
      if (pendingAmbient.has(key) || pendingAmbient.size < MAX_PENDING_AMBIENT_GROUPS) {
        return;
      }
      const oldestKey = pendingAmbient.keys().next().value;
      if (oldestKey !== undefined) {
        pendingAmbient.delete(oldestKey);
        api.logger.warn("marmot: ambient context group limit reached; evicting oldest group");
      }
    };
    const appendPendingAmbient = (key: string, event: MarmotAmbientEvent): void => {
      ensurePendingAmbientGroupCapacity(key);
      const pending = pendingAmbient.get(key) ?? [];
      if (pending.length >= MAX_PENDING_AMBIENT_EVENTS_PER_GROUP) {
        pending.shift();
        api.logger.warn("marmot: ambient context limit reached; evicting oldest fact");
      }
      pending.push(event);
      pendingAmbient.set(key, pending);
    };
    const detachPendingAmbient = (key: string): MarmotAmbientEvent[] => {
      const pending = pendingAmbient.get(key) ?? [];
      pendingAmbient.delete(key);
      return pending;
    };
    const restorePendingAmbient = (key: string, detached: MarmotAmbientEvent[]): void => {
      if (detached.length === 0) {
        return;
      }
      const combined = [...detached, ...(pendingAmbient.get(key) ?? [])];
      const overflow = Math.max(0, combined.length - MAX_PENDING_AMBIENT_EVENTS_PER_GROUP);
      if (overflow > 0) {
        api.logger.warn("marmot: ambient context limit reached; evicting oldest fact");
      }
      ensurePendingAmbientGroupCapacity(key);
      pendingAmbient.set(key, combined.slice(overflow));
    };

    // Per-group serialization: distinct groups dispatch concurrently while each
    // group stays FIFO. A slow/hung turn in one group no longer blocks inbound
    // dispatch for every other group (the previous inline `await dispatch` did).
    const dispatchQueue = new BoundedKeyedAsyncQueue(
      DEFAULT_INBOUND_QUEUE_MAX_DEPTH,
      (message) => api.logger.warn(message),
    );
    const handleInbound = async (message: MarmotInboundMessage): Promise<void> => {
      if (onboardingStore) {
        const intercepted = await maybeHandleProfileOnboardingInbound({
          store: onboardingStore,
          client,
          message: {
            accountIdHex: message.accountIdHex,
            groupIdHex: message.groupIdHex,
            messageIdHex: message.messageIdHex,
            text: message.text,
          },
          configuredName: options.configuredAgentName ?? null,
          logger: api.logger,
        }).catch(() => false); // never block dispatch on an onboarding error
        if (intercepted) {
          return;
        }
      }
      const key = ambientKey(message.accountIdHex, message.groupIdHex);
      // Detach atomically before the turn. Ambient facts arriving while the
      // turn runs now land in a fresh capped batch and cannot be consumed as
      // part of this turn's older snapshot.
      const attachedAmbient = detachPendingAmbient(key);
      const ambientContext = [...(message.ambientContext ?? []), ...attachedAmbient];
      api.logger.info("marmot: inbound message received; dispatching agent turn");
      try {
        const dispatched = await dispatch({ ...message, ambientContext });
        if (dispatched === false) {
          restorePendingAmbient(key, attachedAmbient);
        }
      } catch (error) {
        restorePendingAmbient(key, attachedAmbient);
        throw error;
      }
    };
    const runQueued = (message: MarmotInboundMessage): void => {
      dispatchQueue.enqueue(message.groupIdHex, () => handleInbound(message));
    };
    // Optional debounce: coalesce rapid same-sender/group bursts into a single turn.
    const debouncer =
      resolved.debounceMs > 0
        ? createCompatibleInboundDebouncer<MarmotInboundMessage>({
            debounceMs: resolved.debounceMs,
            buildKey: (message) =>
              `${message.accountIdHex}:${message.groupIdHex}:${message.senderAccountIdHex}`,
            onFlush: (items, createFlush) => {
              const dispatchFlush = async (): Promise<void> => {
                if (items.length > 0) {
                  runQueued(coalesceInboundMessages(items));
                }
              };
              // Beta completion deliberately means "admitted to Marmot's
              // bounded per-group queue", not "the agent turn settled". The
              // outer queue owns turn serialization and failure logging, which
              // matches stable's fire-and-forget seam, so the factory-provided
              // lifecycle argument is intentionally ignored.
              return createFlush
                ? createFlush({ dispatch: async (_lifecycle) => dispatchFlush() })
                : dispatchFlush();
            },
          })
        : null;
    const submitInbound = (message: MarmotInboundMessage): void => {
      if (debouncer) {
        void debouncer
          .enqueue(message)
          .catch(() => api.logger.warn("marmot: inbound debounce failed"));
      } else {
        runQueued(message);
      }
    };

    const bridge = new MarmotInboundBridge(client, {
      accountIdHex,
      groupIdHex: resolved.groupIdHex ?? null,
      onReady: () => {
        markMarmotInboundReady(statusAccountId);
        options.statusSink?.({
          running: true,
          connected: true,
          lastStartAt: Date.now(),
          lastStopAt: null,
          lastError: null,
        });
        api.logger.info(
          readyLogged
            ? "marmot: inbound subscription re-established"
            : "marmot: inbound subscription established",
        );
        readyLogged = true;
      },
      onMessage: (message) => {
        // Non-blocking: record receipt, then hand off to the per-group queue so the
        // inbound loop keeps reading (enables cross-group concurrency). Dedupe in
        // MarmotInboundBridge.handle() already ran synchronously before this.
        markMarmotInboundReceived(statusAccountId);
        options.statusSink?.({ lastInboundAt: Date.now() });
        submitInbound(message);
      },
      onAmbientEvent: (event) => {
        markMarmotInboundReceived(statusAccountId);
        options.statusSink?.({ lastInboundAt: Date.now() });
        api.logger.info("marmot: inbound ambient event observed");
        if (event.type === "group_state_changed") {
          options.invalidateGroupActivation?.(event.account_id_hex, event.group_id_hex);
        }
        const key = ambientKey(event.account_id_hex, event.group_id_hex);
        appendPendingAmbient(key, event);
      },
      onGroupInvite: onboardingStore
        ? async ({ accountIdHex: joinedAccountIdHex, groupIdHex: joinedGroupIdHex }) => {
            markMarmotInboundReceived(statusAccountId);
            options.statusSink?.({ lastInboundAt: Date.now() });
            // Greet on join: offer to publish a public profile name (once).
            await maybeSendProfilePromptOnJoin({
              store: onboardingStore,
              client,
              accountIdHex: joinedAccountIdHex,
              groupIdHex: joinedGroupIdHex,
              configuredName: options.configuredAgentName ?? null,
              logger: api.logger,
            }).catch(() => undefined);
          }
        : undefined,
      onResync: ({ droppedEvents }) => {
        markMarmotInboundReceived(statusAccountId);
        options.statusSink?.({ lastInboundAt: Date.now() });
        api.logger.warn(
          `marmot: inbound resync required (${droppedEvents} broadcast slots dropped)`,
        );
        // Dropped broadcast slots can include a missed group_state_changed for any
        // group, so no cached is_direct fact can be trusted; drop them all.
        options.clearGroupActivationCache?.();
      },
      onError: () => {
        markMarmotInboundReconnect(statusAccountId);
        options.statusSink?.({
          running: true,
          connected: false,
          lastError: "inbound subscription dropped",
        });
        api.logger.warn("marmot: inbound subscription dropped; reconnecting");
      },
    });
    await bridge.run(signal);
  })();

  return () => controller.abort();
}

export interface SyncAllowlistOptions {
  clientFactory?: ClientFactory;
  /** OpenClaw channel account id whose allowlist should be mirrored. */
  channelAccountId?: string | null;
}

/**
 * Mirror the configured `dm.allowFrom` welcomers into wn-agent's allowlist for
 * the resolved account. No-op when no allow-from is configured, so a bare
 * deployment does not wipe an allowlist managed directly on wn-agent.
 */
export async function syncMarmotAllowlist(
  api: InboundPluginApi,
  options: SyncAllowlistOptions = {},
): Promise<void> {
  try {
    const resolved = resolveAccount(api, options.channelAccountId);
    if (resolved.allowFrom.length === 0) {
      return;
    }
    const client = (options.clientFactory ?? clientForAccount)(resolved);
    const accountIdHex = resolved.marmotAccountIdHex ?? (await resolveSingleAccount(client));
    const result = await syncAllowlist(client, accountIdHex, resolved.allowFrom);
    api.logger.info(
      `marmot: welcomer allowlist synced (added ${result.added.length}, removed ${result.removed.length})`,
    );
  } catch {
    // Best-effort on startup: account/config resolution or the sync itself can
    // throw; keep it inside the guard so the voided caller can't reject.
    api.logger.warn("marmot: failed to sync the welcomer allowlist with wn-agent");
  }
}
