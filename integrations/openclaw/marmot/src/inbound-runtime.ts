// Inbound runtime wiring + startup allowlist sync.
//
// `startMarmotInbound` runs the dm-agent inbound subscription and hands each
// mapped message to a real agent dispatcher (no production no-op fallback —
// consuming inbound without dispatching would silently swallow messages). The
// dispatcher in `src/dispatch.ts` drives the OpenClaw turn kernel; the plugin
// entry wires it in `registerFull`. End-to-end behavior is validated against the
// docker `openclaw-gateway` harness (it needs a running gateway + a model).
//
// `syncMarmotAllowlist` mirrors the configured `dm.allowFrom` welcomers into
// dm-agent's per-account allowlist so configured welcomers are accepted.

import { createInboundDebouncer } from "openclaw/plugin-sdk/channel-inbound-debounce";

import { BoundedKeyedAsyncQueue, DEFAULT_INBOUND_QUEUE_MAX_DEPTH } from "./bounded-keyed-async-queue.js";
import { resolveSingleAccount } from "./account.js";
import { resolveMarmotChannelAccount } from "./channel.js";
import type { MarmotAgentControlClient } from "./client.js";
import { clientForAccount, type ResolvedMarmotAccount } from "./config.js";
import { MarmotInboundBridge, type MarmotInboundMessage } from "./inbound.js";
import {
  maybeHandleProfileOnboardingInbound,
  maybeSendProfilePromptOnJoin,
  ProfileNameOnboardingStore,
} from "./profile-onboarding.js";
import {
  markMarmotInboundReady,
  markMarmotInboundReceived,
  markMarmotInboundReconnect,
  markMarmotInboundStarting,
  markMarmotInboundStopped,
} from "./runtime-state.js";
import { syncAllowlist } from "./security.js";

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

function resolveAccount(api: InboundPluginApi): ResolvedMarmotAccount {
  return resolveMarmotChannelAccount(
    api.config as Parameters<typeof resolveMarmotChannelAccount>[0],
    null,
  );
}

/**
 * Map a coarse group-state change kind to a short, privacy-safe sentence for
 * ambient agent context. NEVER includes a member pubkey; the only detail
 * surfaced is the new group name on a rename (already non-secret group metadata).
 */
function groupStateChangeSentence(change: string, detail?: string | null): string {
  switch (change) {
    case "member_added":
      return "A member was added to the group.";
    case "member_removed":
      return "A member was removed from the group.";
    case "member_left":
      return "A member left the group.";
    case "admin_added":
      return "A member was made a group admin.";
    case "admin_removed":
      return "A member is no longer a group admin.";
    case "group_renamed":
      return detail && detail.trim().length > 0
        ? `The group was renamed to "${detail.trim()}".`
        : "The group was renamed.";
    case "group_avatar_changed":
      return "The group avatar was changed.";
    default:
      return "The group state changed.";
  }
}

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
    media,
  };
}

export type InboundAgentDispatcher = (message: MarmotInboundMessage) => void | Promise<void>;

/**
 * A passive ambient event surfaced to the agent as next-turn context (no reply
 * is triggered). `groupIdHex` selects the agent session; `text` is a short,
 * privacy-safe sentence; `contextKey` dedupes repeated surfacings of the same
 * fact. Built in `index.ts` over the full plugin api (it needs
 * `api.runtime.system`/`api.runtime.channel`, which the narrowed
 * `InboundPluginApi` does not expose) and passed in here.
 */
export type MarmotAmbientSurfacer = (event: {
  accountIdHex: string;
  groupIdHex: string;
  text: string;
  contextKey?: string;
}) => void | Promise<void>;

export interface StartMarmotInboundOptions {
  signal?: AbortSignal;
  /** Override the control-client factory (tests inject a stub). */
  clientFactory?: ClientFactory;
  /**
   * Configured OpenClaw agent name. When profile-name onboarding is enabled and
   * a name is present, it is inherited and published instead of asking in-chat.
   */
  configuredAgentName?: string | null;
  /**
   * Surface passive group events (a deletion, a membership/rename change) to the
   * agent as quiet next-turn context. When omitted, those events are only logged.
   */
  surfaceAmbientEvent?: MarmotAmbientSurfacer;
  /**
   * Invalidate the dispatcher's cached `is_direct` activation fact for one group.
   * Called when dm-agent reports a `group_state_changed` event so the next
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

// The gateway can full-load the plugin in more than one in-process context
// (the HTTP server and the agent-runtime pre-warm each invoke `registerFull`),
// so `startMarmotInbound` can be called more than once in a single process. A
// second live subscription would deliver — and dispatch an agent turn for —
// every inbound message twice, so only the first start is honored until it is
// stopped.
let inboundActive = false;

/**
 * Run the dm-agent inbound subscription, dispatching each mapped message to
 * `dispatch`. Returns a stop function that aborts the loop. Requires a real
 * dispatcher — see the module note.
 */
export function startMarmotInbound(
  api: InboundPluginApi,
  dispatch: InboundAgentDispatcher,
  options: StartMarmotInboundOptions = {},
): () => void {
  if (inboundActive) {
    api.logger.info("marmot: inbound subscription already active; ignoring duplicate start");
    return () => {};
  }
  const resolved = resolveAccount(api);
  const statusAccountId = resolved.accountId ?? null;
  inboundActive = true;
  markMarmotInboundStarting(statusAccountId);
  const controller = new AbortController();
  // Release the guard when the loop is stopped so a clean restart can re-subscribe.
  controller.signal.addEventListener(
    "abort",
    () => {
      inboundActive = false;
      markMarmotInboundStopped(statusAccountId);
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
      inboundActive = false;
      markMarmotInboundStopped(statusAccountId);
      return;
    }
    let readyLogged = false;

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
      api.logger.info("marmot: inbound message received; dispatching agent turn");
      await dispatch(message);
    };
    const runQueued = (message: MarmotInboundMessage): void => {
      dispatchQueue.enqueue(message.groupIdHex, () => handleInbound(message));
    };
    // Optional debounce: coalesce rapid same-sender/group bursts into a single turn.
    const debouncer =
      resolved.debounceMs > 0
        ? createInboundDebouncer<MarmotInboundMessage>({
            debounceMs: resolved.debounceMs,
            buildKey: (message) =>
              `${message.accountIdHex}:${message.groupIdHex}:${message.senderAccountIdHex}`,
            onFlush: async (items) => {
              if (items.length > 0) {
                runQueued(coalesceInboundMessages(items));
              }
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
        submitInbound(message);
      },
      onMessageDeleted: (deletion) => {
        // A peer retracted a message. Surface it to the agent as quiet ambient
        // (next-turn) context when a surfacer is wired; always recorded + logged
        // privacy-safely (no ids/pubkeys in the log).
        markMarmotInboundReceived(statusAccountId);
        api.logger.info("marmot: inbound message deletion observed");
        void Promise.resolve(
          options.surfaceAmbientEvent?.({
            accountIdHex: deletion.accountIdHex,
            groupIdHex: deletion.groupIdHex,
            text: "A message was deleted.",
            contextKey: `marmot:message_deleted:${deletion.groupIdHex}:${deletion.targetMessageIdHex}`,
          }),
        ).catch(() => api.logger.warn("marmot: failed to surface message deletion to the agent"));
      },
      onGroupStateChanged: (change) => {
        // A durable group-state change (membership/admin/rename/avatar) was
        // observed. The change kind contents are NOT logged; they ARE surfaced to
        // the agent as quiet ambient context (via the surfacer) when wired. The
        // mapped sentence never carries a member pubkey.
        markMarmotInboundReceived(statusAccountId);
        api.logger.info("marmot: inbound group state change observed");
        // Drop the cached is_direct activation fact for this group: a
        // membership change can flip whether the group is an effective DM, so the
        // next unaddressed message must re-read fresh membership.
        options.invalidateGroupActivation?.(change.accountIdHex, change.groupIdHex);
        void Promise.resolve(
          options.surfaceAmbientEvent?.({
            accountIdHex: change.accountIdHex,
            groupIdHex: change.groupIdHex,
            text: groupStateChangeSentence(change.change, change.detail),
            contextKey: `marmot:group_state_changed:${change.groupIdHex}:${change.change}`,
          }),
        ).catch(() =>
          api.logger.warn("marmot: failed to surface group state change to the agent"),
        );
      },
      onGroupInvite: onboardingStore
        ? async ({ accountIdHex: joinedAccountIdHex, groupIdHex: joinedGroupIdHex }) => {
            markMarmotInboundReceived(statusAccountId);
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
        api.logger.warn(
          `marmot: inbound resync required (${droppedEvents} broadcast slots dropped)`,
        );
        // Dropped broadcast slots can include a missed group_state_changed for any
        // group, so no cached is_direct fact can be trusted; drop them all.
        options.clearGroupActivationCache?.();
      },
      onError: () => {
        markMarmotInboundReconnect(statusAccountId);
        api.logger.warn("marmot: inbound subscription dropped; reconnecting");
      },
    });
    await bridge.run(signal);
  })();

  return () => controller.abort();
}

export interface SyncAllowlistOptions {
  clientFactory?: ClientFactory;
}

/**
 * Mirror the configured `dm.allowFrom` welcomers into dm-agent's allowlist for
 * the resolved account. No-op when no allow-from is configured, so a bare
 * deployment does not wipe an allowlist managed directly on dm-agent.
 */
export async function syncMarmotAllowlist(
  api: InboundPluginApi,
  options: SyncAllowlistOptions = {},
): Promise<void> {
  try {
    const resolved = resolveAccount(api);
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
    api.logger.warn("marmot: failed to sync the welcomer allowlist with dm-agent");
  }
}
