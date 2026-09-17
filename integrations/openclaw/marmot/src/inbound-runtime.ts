// Inbound runtime wiring + startup allowlist sync.
//
// `startMarmotInbound` runs the wn-agent inbound subscription and hands each
// mapped message to a real agent dispatcher (no production no-op fallback —
// consuming inbound without dispatching would silently swallow messages). The
// dispatcher in `src/dispatch.ts` drives the OpenClaw turn kernel; the channel's
// `gateway.startAccount` task owns this runtime for its full lifetime.
//
// `syncMarmotAllowlist` mirrors the configured `dm.allowFrom` welcomers into
// wn-agent's per-account allowlist so configured welcomers are accepted, and
// returns a typed readiness result the gateway can retain and retry.

import { createInboundDebouncer } from "openclaw/plugin-sdk/channel-inbound-debounce";
import type { ChannelAccountSnapshot } from "openclaw/plugin-sdk/status-helpers";

import { resolveSingleAccount } from "./account.js";
import {
  BoundedKeyedAsyncQueue,
  DEFAULT_INBOUND_QUEUE_MAX_DEPTH,
  DEFAULT_INBOUND_QUEUE_MAX_TRACKED_GROUPS,
} from "./bounded-keyed-async-queue.js";
import { resolveMarmotChannelAccount, selectMarmotChannelAccountConfig } from "./channel.js";
import type { MarmotAgentControlClient } from "./client.js";
import { clientForAccount, type ResolvedMarmotAccount } from "./config.js";
import {
  MarmotInboundBridge,
  type MarmotAmbientEvent,
  type MarmotInboundCompletionOutcome,
  type MarmotInboundMessage,
  type MarmotInboundSubmission,
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
  markMarmotInboundSetupFailed,
  markMarmotInboundStarting,
  markMarmotInboundStopped,
  marmotInboundRuntimeSnapshot,
  type MarmotAllowlistSyncResult,
} from "./runtime-state.js";
import { syncAllowlist } from "./security.js";

export type {
  MarmotAllowlistSyncFailureReason,
  MarmotAllowlistSyncResult,
} from "./runtime-state.js";

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

interface CompatibleInboundDebounceAdmissionLifecycle {
  onAdopted: () => void | Promise<void>;
}

type CompatibleInboundDebounceFlushFactory = (params: {
  dispatch: (lifecycle: CompatibleInboundDebounceAdmissionLifecycle) => Promise<void>;
}) => CompatibleInboundDebounceFlush;

type CompatibleInboundDebouncerFactory = <T>(params: {
  debounceMs: number;
  maxTrackedKeys?: number;
  buildKey: (item: T) => string | null | undefined;
  onFlush: (
    items: T[],
    createFlush?: CompatibleInboundDebounceFlushFactory,
  ) => Promise<void> | CompatibleInboundDebounceFlush;
  onCancel?: (items: T[]) => void;
}) => {
  enqueue: (item: T) => Promise<void>;
  cancelKey: (key: string) => boolean;
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
const DEFAULT_INBOUND_DEBOUNCE_MAX_DEPTH_PER_KEY = DEFAULT_INBOUND_QUEUE_MAX_DEPTH;
const DEFAULT_INBOUND_DEBOUNCE_MAX_TRACKED_KEYS = DEFAULT_INBOUND_QUEUE_MAX_TRACKED_GROUPS;

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
   * Invalidate the dispatcher's cached group-info facts for one group
   * (`is_direct` plus the normalized subject). Called when wn-agent reports a
   * `group_state_changed` event — including rename — so the next relevant turn
   * re-reads authoritative `group_info` instead of a stale cached value. Event
   * `detail` is never treated as a separately maintained label. When omitted,
   * the cache is never invalidated from here.
   */
  invalidateGroupActivation?: (accountIdHex: string, groupIdHex: string) => void;
  /**
   * Drop every cached group-info fact and in-flight generation. Called on an
   * inbound resync, subscription drop, or clean-EOF reconnect, where a missed
   * `group_state_changed` (including rename) means no cached membership or
   * subject can be trusted.
   */
  clearGroupActivationCache?: () => void;
  /**
   * Optional reconnect delay overrides. Production keeps the bridge defaults;
   * tests inject a short delay so live rename/resync/reconnect coverage does
   * not sit on the 1s base backoff.
   */
  reconnectDelayMs?: number;
  maxReconnectDelayMs?: number;
  /**
   * Gateway-owned recovery hook when asynchronous account/config/client setup
   * fails before the subscription is active. Not invoked after a clean stop.
   */
  onSetupFailed?: () => void;
}

// OpenClaw owns one gateway task per configured channel account. Keep one
// subscription per account even if a host accidentally starts the same task
// twice. The reservation token lets a replaced attempt release only itself.
const inboundActiveAccounts = new Map<string, symbol>();

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
  let inboundAccountKey = "";
  let statusAccountId = "";
  let resolved: ResolvedMarmotAccount;
  try {
    resolved = resolveAccount(api, options.channelAccountId);
    inboundAccountKey =
      options.channelAccountId?.trim() ||
      resolved.accountId ||
      DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
    if (inboundActiveAccounts.has(inboundAccountKey)) {
      api.logger.info("marmot: inbound subscription already active; ignoring duplicate start");
      return () => {};
    }
    statusAccountId = resolved.accountId ?? inboundAccountKey;
    inboundActiveAccounts.set(inboundAccountKey, Symbol("marmot-inbound-attempt"));
  } catch {
    api.logger.warn("marmot: could not resolve an agent account for the inbound subscription");
    const failedAccountId =
      options.channelAccountId?.trim() || DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
    markMarmotInboundSetupFailed(failedAccountId);
    options.statusSink?.(marmotInboundRuntimeSnapshot(failedAccountId));
    options.onSetupFailed?.();
    return () => {};
  }
  const attemptId = inboundActiveAccounts.get(inboundAccountKey)!;
  const publishStatus = (): void => {
    options.statusSink?.(marmotInboundRuntimeSnapshot(statusAccountId));
  };
  markMarmotInboundStarting(statusAccountId);
  publishStatus();
  const controller = new AbortController();
  let stopping = false;
  let disposed = false;
  let cancelPendingDebounce = (): void => undefined;
  let stopInbound: () => void = () => {};
  const ownsReservation = (): boolean =>
    inboundActiveAccounts.get(inboundAccountKey) === attemptId;
  const onExternalAbort = (): void => {
    stopInbound();
  };
  const dispose = (mode: "stop" | "setup-failed"): boolean => {
    if (disposed) {
      return false;
    }
    disposed = true;
    stopping = true;
    cancelPendingDebounce();
    options.signal?.removeEventListener("abort", onExternalAbort);
    const owned = ownsReservation();
    if (owned) {
      inboundActiveAccounts.delete(inboundAccountKey);
    }
    if (!controller.signal.aborted) {
      controller.abort();
    }
    if (!owned) {
      return false;
    }
    if (mode === "setup-failed") {
      markMarmotInboundSetupFailed(statusAccountId);
    } else {
      markMarmotInboundStopped(statusAccountId);
    }
    publishStatus();
    return true;
  };
  stopInbound = (): void => {
    dispose("stop");
  };
  const failSetup = (): void => {
    const alreadyStopping = stopping;
    dispose("setup-failed");
    if (!alreadyStopping) {
      options.onSetupFailed?.();
    }
  };
  // Always drive the loop off the internal controller so the returned stop() is
  // authoritative. Route external aborts through that same idempotent dispose
  // path so a failed or replaced attempt cannot leak listeners or mutate a
  // newer reservation.
  controller.signal.addEventListener(
    "abort",
    () => {
      dispose("stop");
    },
    { once: true },
  );
  if (options.signal) {
    if (options.signal.aborted) {
      stopInbound();
    } else {
      options.signal.addEventListener("abort", onExternalAbort);
    }
  }
  const signal = controller.signal;
  let client: MarmotAgentControlClient;
  try {
    client = (options.clientFactory ?? clientForAccount)(resolved);
  } catch {
    failSetup();
    return stopInbound;
  }
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
      failSetup();
      return;
    }
    if (stopping || !ownsReservation()) {
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
      (signal) =>
        api.logger.warn(
          `marmot: inbound queue overloaded (reason=${signal.reason}, active_groups=${signal.activeGroups}, max_depth_per_group=${signal.maxDepthPerGroup}, max_tracked_groups=${signal.maxTrackedGroups})`,
        ),
      undefined,
      (message) => api.logger.warn(message),
    );
    const handleInbound = async (
      message: MarmotInboundMessage,
    ): Promise<MarmotInboundCompletionOutcome> => {
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
          return "onboarding_intercepted";
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
          return "not_dispatched";
        }
        return "dispatched";
      } catch (error) {
        restorePendingAmbient(key, attachedAmbient);
        throw error;
      }
    };
    const runQueued = (message: MarmotInboundMessage): MarmotInboundSubmission => {
      let resolveCompletion!: (outcome: MarmotInboundCompletionOutcome) => void;
      let rejectCompletion!: (error: unknown) => void;
      const completion = new Promise<MarmotInboundCompletionOutcome>((resolve, reject) => {
        resolveCompletion = resolve;
        rejectCompletion = reject;
      });
      void completion.catch(() => undefined);
      const admission = dispatchQueue.enqueue(message.groupIdHex, async () => {
        try {
          resolveCompletion(await handleInbound(message));
        } catch (error) {
          rejectCompletion(error);
          throw error;
        }
      });
      if (admission.outcome === "overloaded") {
        resolveCompletion("overloaded");
        return { admission: "overloaded", completion };
      }
      return { admission: "admitted", completion };
    };
    interface PendingDebounceItem {
      message: MarmotInboundMessage;
      resolve: (submission: MarmotInboundSubmission) => void;
    }
    const retryableCancellation = (): MarmotInboundSubmission => ({
      admission: "overloaded",
      completion: Promise.resolve("overloaded"),
    });
    const coalescedSubmission = (
      completion: Promise<MarmotInboundCompletionOutcome>,
    ): MarmotInboundSubmission => ({
      admission: "coalesced",
      completion: completion.then(() => "coalesced"),
    });
    const pendingDebounceDepths = new Map<string, number>();
    const releasePendingDebounce = (key: string): void => {
      const next = (pendingDebounceDepths.get(key) ?? 1) - 1;
      if (next <= 0) {
        pendingDebounceDepths.delete(key);
      } else {
        pendingDebounceDepths.set(key, next);
      }
    };
    const flushInboundBatch = (
      items: PendingDebounceItem[],
      lifecycle?: CompatibleInboundDebounceAdmissionLifecycle,
    ): Promise<void> => {
      if (items.length === 0) {
        return Promise.resolve();
      }
      if (stopping) {
        for (const item of items) {
          item.resolve(retryableCancellation());
        }
        return Promise.resolve();
      }
      const queued = runQueued(coalesceInboundMessages(items.map((item) => item.message)));
      if (queued.admission === "overloaded") {
        for (const item of items) {
          item.resolve(queued);
        }
        return queued.completion.then(() => undefined);
      }
      const representativeIndex = items.length - 1;
      items.forEach((item, index) => {
        item.resolve(
          index === representativeIndex ? queued : coalescedSubmission(queued.completion),
        );
      });
      const admission = Promise.resolve(lifecycle?.onAdopted());
      // Stable uses the returned Promise to serialize this debounce key. Release
      // that lane once the group queue adopts the batch; each submission keeps
      // the real turn completion separately. Beta's lifecycle wrapper still
      // needs this dispatch Promise to represent completion.
      return lifecycle
        ? admission.then(() => queued.completion).then(() => undefined)
        : admission;
    };
    // Optional debounce: coalesce rapid same-sender/group bursts into a single turn.
    const debouncer =
      resolved.debounceMs > 0
        ? createCompatibleInboundDebouncer<PendingDebounceItem>({
            debounceMs: resolved.debounceMs,
            maxTrackedKeys: DEFAULT_INBOUND_DEBOUNCE_MAX_TRACKED_KEYS,
            buildKey: ({ message }) =>
              `${message.accountIdHex}:${message.groupIdHex}:${message.senderAccountIdHex}`,
            onFlush: (items, createFlush) => {
              // Stable awaits this Promise directly. Beta's factory publishes
              // separate admission/completion promises around the same dispatch.
              // Mark adoption as soon as the group queue accepts the batch so
              // beta can release this debounce key while the turn completes.
              return createFlush
                ? createFlush({ dispatch: (lifecycle) => flushInboundBatch(items, lifecycle) })
                : flushInboundBatch(items);
            },
            onCancel: (items) => {
              for (const item of items) {
                item.resolve(retryableCancellation());
              }
            },
          })
        : null;
    cancelPendingDebounce = () => {
      if (!debouncer) {
        return;
      }
      for (const key of [...pendingDebounceDepths.keys()]) {
        debouncer.cancelKey(key);
      }
    };
    const submitInbound = (
      message: MarmotInboundMessage,
    ): MarmotInboundSubmission | Promise<MarmotInboundSubmission> => {
      if (stopping) {
        return retryableCancellation();
      }
      if (debouncer) {
        const key = `${message.accountIdHex}:${message.groupIdHex}:${message.senderAccountIdHex}`;
        const depth = pendingDebounceDepths.get(key) ?? 0;
        const reason =
          depth >= DEFAULT_INBOUND_DEBOUNCE_MAX_DEPTH_PER_KEY
            ? "per_key_depth"
            : depth === 0 &&
                pendingDebounceDepths.size >= DEFAULT_INBOUND_DEBOUNCE_MAX_TRACKED_KEYS
              ? "tracked_key_limit"
              : null;
        if (reason) {
          api.logger.warn(
            `marmot: inbound debounce overloaded (reason=${reason}, active_keys=${pendingDebounceDepths.size}, max_depth_per_key=${DEFAULT_INBOUND_DEBOUNCE_MAX_DEPTH_PER_KEY}, max_tracked_keys=${DEFAULT_INBOUND_DEBOUNCE_MAX_TRACKED_KEYS})`,
          );
          return { admission: "overloaded", completion: Promise.resolve("overloaded") };
        }
        pendingDebounceDepths.set(key, depth + 1);
        let resolveSubmission!: (submission: MarmotInboundSubmission) => void;
        let rejectSubmission!: (error: unknown) => void;
        const submission = new Promise<MarmotInboundSubmission>((resolve, reject) => {
          resolveSubmission = resolve;
          rejectSubmission = reject;
        });
        let admissionSettled = false;
        const settleSubmission = (settled: MarmotInboundSubmission): void => {
          if (admissionSettled) {
            return;
          }
          admissionSettled = true;
          releasePendingDebounce(key);
          resolveSubmission(settled);
        };
        void debouncer
          .enqueue({ message, resolve: settleSubmission })
          .catch((error: unknown) => {
            if (admissionSettled) {
              return;
            }
            admissionSettled = true;
            releasePendingDebounce(key);
            rejectSubmission(error);
            api.logger.warn("marmot: inbound debounce failed");
          });
        return submission;
      }
      return runQueued(message);
    };

    const bridge = new MarmotInboundBridge(client, {
      accountIdHex,
      groupIdHex: resolved.groupIdHex ?? null,
      reconnectDelayMs: options.reconnectDelayMs,
      maxReconnectDelayMs: options.maxReconnectDelayMs,
      onReady: () => {
        if (stopping || !ownsReservation()) {
          return;
        }
        if (readyLogged) {
          // Clean EOF or post-error reconnect can miss a rename while the
          // socket was down; drop every fact and pending generation.
          options.clearGroupActivationCache?.();
        }
        markMarmotInboundReady(statusAccountId);
        publishStatus();
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
        publishStatus();
        return submitInbound(message);
      },
      onAmbientEvent: (event) => {
        markMarmotInboundReceived(statusAccountId);
        publishStatus();
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
            publishStatus();
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
        publishStatus();
        api.logger.warn(
          `marmot: inbound resync required (${droppedEvents} broadcast slots dropped)`,
        );
        // Dropped broadcast slots can include a missed group_state_changed for any
        // group, so no cached membership or subject can be trusted; drop them all.
        options.clearGroupActivationCache?.();
      },
      onSubmissionError: () => {
        api.logger.warn("marmot: inbound submission failed before admission; replay remains retryable");
      },
      onError: () => {
        options.clearGroupActivationCache?.();
        markMarmotInboundReconnect(statusAccountId);
        publishStatus();
        api.logger.warn("marmot: inbound subscription dropped; reconnecting");
      },
    });
    await bridge.run(signal);
  })();

  return stopInbound;
}

export interface SyncAllowlistOptions {
  clientFactory?: ClientFactory;
  /** OpenClaw channel account id whose allowlist should be mirrored. */
  channelAccountId?: string | null;
}

function warnAllowlistFailure(api: InboundPluginApi): void {
  api.logger.warn("marmot: failed to sync the welcomer allowlist with wn-agent");
}

/**
 * Mirror the configured `dm.allowFrom` welcomers into wn-agent's allowlist for
 * the resolved account. Absent or empty `allowFrom` is unmanaged: no control
 * client, account query, list read, or mutation, so a bare deployment does not
 * wipe an allowlist managed directly on wn-agent.
 *
 * Inbound dispatch is not blocked on reconciliation. Failures return a typed
 * result and aggregate warnings rather than throwing. A failed revocation gets
 * its own warning: it is the one outcome that leaves the account more
 * permissive than the operator asked for.
 */
export async function syncMarmotAllowlist(
  api: InboundPluginApi,
  options: SyncAllowlistOptions = {},
): Promise<MarmotAllowlistSyncResult> {
  let allowFrom: Array<string | number>;
  try {
    const selected = selectMarmotChannelAccountConfig(
      api.config as Parameters<typeof selectMarmotChannelAccountConfig>[0],
      options.channelAccountId ?? null,
    );
    allowFrom = selected.config.dm?.allowFrom ?? [];
  } catch {
    warnAllowlistFailure(api);
    return { state: "failed", reason: "config_resolution" };
  }
  if (allowFrom.length === 0) {
    return { state: "unmanaged" };
  }

  let resolved: ResolvedMarmotAccount;
  try {
    resolved = resolveAccount(api, options.channelAccountId);
  } catch {
    warnAllowlistFailure(api);
    return { state: "failed", reason: "config_resolution" };
  }

  let client: MarmotAgentControlClient;
  try {
    client = (options.clientFactory ?? clientForAccount)(resolved);
  } catch {
    warnAllowlistFailure(api);
    return { state: "failed", reason: "control" };
  }

  let accountIdHex: string;
  try {
    accountIdHex = resolved.marmotAccountIdHex ?? (await resolveSingleAccount(client));
  } catch {
    warnAllowlistFailure(api);
    return { state: "failed", reason: "account_resolution" };
  }

  try {
    const result = await syncAllowlist(client, accountIdHex, allowFrom);
    if (result.failedRemovals.length > 0) {
      // Fail-open risk: those welcomers stay authorized on the shared account
      // until the next successful sync, so never let it read as a clean start.
      api.logger.warn(
        `marmot: welcomer allowlist revocation failed for ${result.failedRemovals.length} entries; they remain authorized on wn-agent`,
      );
    }
    if (result.verified) {
      api.logger.info(
        `marmot: welcomer allowlist synced (added ${result.added.length}, removed ${result.removed.length})`,
      );
      return { state: "reconciled" };
    }
    api.logger.warn(
      `marmot: welcomer allowlist not reconciled (added ${result.added.length}, removed ${result.removed.length}, failed ${result.failedAdds.length + result.failedRemovals.length})`,
    );
    return { state: "failed", reason: "unverified" };
  } catch {
    warnAllowlistFailure(api);
    return { state: "failed", reason: "control" };
  }
}
