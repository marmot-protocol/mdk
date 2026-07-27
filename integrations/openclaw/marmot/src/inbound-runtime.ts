// Inbound runtime wiring + startup allowlist sync.
//
// `startMarmotInbound` runs the wn-agent inbound subscription and hands each
// mapped message to a real agent dispatcher (no production no-op fallback —
// consuming inbound without dispatching would silently swallow messages). The
// dispatcher in `src/dispatch.ts` drives the OpenClaw turn kernel; the plugin
// entry wires it in `registerFull`. End-to-end behavior is validated against the
// docker `openclaw-gateway` harness (it needs a running gateway + a model).
//
// `syncMarmotAllowlist` mirrors the configured `dm.allowFrom` welcomers into
// wn-agent's per-account allowlist so configured welcomers are accepted.

import { createInboundDebouncer } from "openclaw/plugin-sdk/channel-inbound-debounce";

import type { ChannelAccountSnapshot } from "openclaw/plugin-sdk/status-helpers";

import { BoundedKeyedAsyncQueue, DEFAULT_INBOUND_QUEUE_MAX_DEPTH } from "./bounded-keyed-async-queue.js";
import { resolveSingleAccount } from "./account.js";
import { resolveMarmotChannelAccount } from "./channel.js";
import type { MarmotAgentControlClient } from "./client.js";
import { clientForAccount, type ResolvedMarmotAccount } from "./config.js";
import {
  MarmotDispatchAmbiguousDeliveryError,
  MarmotDispatchDeliveryFailedError,
  MarmotDispatchNotReadyError,
} from "./dispatch-errors.js";
import {
  inboundDedupeForAccount,
  MarmotInboundBridge,
  resetInboundDedupeForTests,
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

function resolveConfiguredAccount(
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
    case "disappearing_timer_changed":
      return "The disappearing-message timer was changed.";
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
    coalescedMessageIdsHex: items.map((item) => item.messageIdHex),
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
  /** OpenClaw channel account id for multi-account deployments. */
  channelAccountId?: string;
  /** Gateway-owned status writer; preferred over the legacy runtime-state shim. */
  statusSink?: (patch: Partial<ChannelAccountSnapshot>) => void;
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
  /** Override per-group inbound dispatch queue depth (tests). */
  inboundQueueMaxDepth?: number;
}

// Per OpenClaw channel account: only one live subscription at a time.
const inboundActiveByAccount = new Map<string, boolean>();

const DISPATCH_NOT_READY_MAX_ATTEMPTS = 3;
const DISPATCH_NOT_READY_BACKOFF_MS = [50, 100, 200] as const;

/** Sleep between bounded readiness retries. */
async function sleepMs(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

/** Resolve the stable per-channel-account key used for guards and dedupe. */
function resolveInboundAccountKey(
  api: InboundPluginApi,
  channelAccountId?: string | null,
): string {
  if (channelAccountId?.trim()) {
    return channelAccountId.trim();
  }
  try {
    return resolveConfiguredAccount(api, channelAccountId).accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
  } catch {
    return DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
  }
}

/** Clear per-account subscription guards and dedupe between isolated tests. */
export function resetMarmotInboundAccountsForTests(): void {
  inboundActiveByAccount.clear();
  resetInboundDedupeForTests();
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
  const inboundAccountKey = resolveInboundAccountKey(api, options.channelAccountId);
  if (inboundActiveByAccount.get(inboundAccountKey)) {
    api.logger.info("marmot: inbound subscription already active; ignoring duplicate start");
    return () => {};
  }
  const resolved = resolveMarmotChannelAccount(
    api.config as Parameters<typeof resolveMarmotChannelAccount>[0],
    options.channelAccountId ?? null,
  );
  // Complete synchronous construction before claiming the per-account guard. A
  // bad socket/config or onboarding-store path must not poison later restarts.
  const client = (options.clientFactory ?? clientForAccount)(resolved);
  const onboardingStore = resolved.profileNameOnboarding
    ? new ProfileNameOnboardingStore(resolved.profileOnboardingStatePath)
    : null;
  const statusAccountId = resolved.accountId ?? inboundAccountKey;
  inboundActiveByAccount.set(inboundAccountKey, true);
  const publishStatus = (patch: Partial<ChannelAccountSnapshot>) => {
    options.statusSink?.({ accountId: statusAccountId, ...patch });
    if (!options.statusSink) {
      if (patch.running === true && patch.connected === true) {
        markMarmotInboundReady(statusAccountId);
      } else if (patch.running === true && patch.connected === false) {
        if (patch.lastError) {
          markMarmotInboundReconnect(statusAccountId);
        } else {
          markMarmotInboundStarting(statusAccountId);
        }
      } else if (patch.running === false) {
        markMarmotInboundStopped(statusAccountId);
      } else if (patch.lastInboundAt) {
        markMarmotInboundReceived(statusAccountId);
      }
    }
  };
  publishStatus({ running: true, connected: false, lastStartAt: Date.now(), lastStopAt: null, lastError: null });
  const controller = new AbortController();
  // Release the guard when the loop is stopped so a clean restart can re-subscribe.
  controller.signal.addEventListener(
    "abort",
    () => {
      inboundActiveByAccount.delete(inboundAccountKey);
      publishStatus({ running: false, connected: false, lastStopAt: Date.now() });
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

  void (async () => {
    let accountIdHex: string;
    try {
      accountIdHex = resolved.marmotAccountIdHex ?? (await resolveSingleAccount(client));
    } catch {
      api.logger.warn("marmot: could not resolve an agent account for the inbound subscription");
      inboundActiveByAccount.delete(inboundAccountKey);
      publishStatus({ running: false, connected: false, lastStopAt: Date.now() });
      return;
    }
    let readyLogged = false;

    // Per-group serialization: distinct groups dispatch concurrently while each
    // group stays FIFO. A slow/hung turn in one group no longer blocks inbound
    // dispatch for every other group (the previous inline `await dispatch` did).
    const dispatchQueue = new BoundedKeyedAsyncQueue(
      options.inboundQueueMaxDepth ?? DEFAULT_INBOUND_QUEUE_MAX_DEPTH,
      (message) => api.logger.warn(message),
    );
    const inboundDedupe = inboundDedupeForAccount(inboundAccountKey);
    const rollbackInboundDedupe = (message: MarmotInboundMessage): void => {
      const ids = message.coalescedMessageIdsHex ?? [message.messageIdHex];
      for (const id of ids) {
        inboundDedupe.remove(id);
      }
    };
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
      for (let attempt = 0; attempt < DISPATCH_NOT_READY_MAX_ATTEMPTS; attempt += 1) {
        if (signal.aborted) {
          rollbackInboundDedupe(message);
          return;
        }
        try {
          await dispatch(message);
          return;
        } catch (error) {
          if (
            error instanceof MarmotDispatchAmbiguousDeliveryError ||
            error instanceof MarmotDispatchDeliveryFailedError
          ) {
            // These failures are explicitly replay-safe: the turn identity is
            // deterministic and wn-agent either reuses the committed receipt or
            // rejects a regenerated payload under the same key. Clear every
            // coalesced source id so reconnect redelivery can run that replay.
            rollbackInboundDedupe(message);
            throw error;
          }
          if (!(error instanceof MarmotDispatchNotReadyError)) {
            throw error;
          }
          const exhausted =
            error.reason === "non_retryable" || attempt >= DISPATCH_NOT_READY_MAX_ATTEMPTS - 1;
          if (exhausted) {
            rollbackInboundDedupe(message);
            api.logger.warn(
              error.reason === "non_retryable"
                ? "marmot: inbound dispatch failed (readiness non-retryable)"
                : "marmot: inbound dispatch failed after readiness exhaustion",
            );
            throw error;
          }
          if (signal.aborted) {
            rollbackInboundDedupe(message);
            return;
          }
          api.logger.warn("marmot: inbound dispatch not ready; retrying after backoff");
          await sleepMs(DISPATCH_NOT_READY_BACKOFF_MS[attempt] ?? 100);
          if (signal.aborted) {
            rollbackInboundDedupe(message);
            return;
          }
        }
      }
    };
    const runQueued = (message: MarmotInboundMessage): void => {
      const accepted = dispatchQueue.enqueue(message.groupIdHex, () => handleInbound(message));
      if (!accepted) {
        rollbackInboundDedupe(message);
      }
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
      dedupe: inboundDedupe,
      onReady: () => {
        publishStatus({
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
        publishStatus({ lastInboundAt: Date.now() });
        submitInbound(message);
      },
      onMessageDeleted: (deletion) => {
        publishStatus({ lastInboundAt: Date.now() });
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
        publishStatus({ lastInboundAt: Date.now() });
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
            publishStatus({ lastInboundAt: Date.now() });
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
        publishStatus({ lastInboundAt: Date.now() });
        api.logger.warn(
          `marmot: inbound resync required (${droppedEvents} broadcast slots dropped)`,
        );
        // Dropped broadcast slots can include a missed group_state_changed for any
        // group, so no cached is_direct fact can be trusted; drop them all.
        options.clearGroupActivationCache?.();
      },
      onError: () => {
        publishStatus({
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
  /** OpenClaw channel account id for multi-account deployments. */
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
    const resolved = resolveConfiguredAccount(api, options.channelAccountId);
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
