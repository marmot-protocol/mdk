// Turn-scoped durable reply ownership via AsyncLocalStorage.
//
// Coordinates the bound MarmotReplySink and outbound message-tool sends so an
// inbound turn commits at most one durable reply to its source route. Scoped to
// the active inbound dispatch — never a global or last-seen route cache.

import { AsyncLocalStorage } from "node:async_hooks";

import { MarmotDispatchAmbiguousDeliveryError } from "./dispatch-errors.js";

/** Immutable route identity for one inbound Marmot agent turn. */
export interface MarmotTurnRoute {
  readonly channelAccountId: string;
  readonly marmotAccountIdHex: string;
  readonly groupIdHex: string;
  readonly replyToMessageIdHex: string;
  readonly idempotencyKey: string;
}

export type MarmotTurnDurableOwner = "none" | "sink" | "outbound";

/** Same-route outbound send rejected because the sink already owns durable delivery. */
export class MarmotTurnDurableOwnershipError extends Error {
  constructor() {
    super("marmot: durable reply already owned for this turn");
    this.name = "MarmotTurnDurableOwnershipError";
  }
}

export interface MarmotTurnOutboundReceipt {
  messageIdsHex: string[];
}

export interface MarmotTurnDeliveryState {
  route: MarmotTurnRoute;
  durableOwner: MarmotTurnDurableOwner;
  /** True after a same-route outbound send succeeded for this turn. */
  outboundDelivered: boolean;
  /**
   * True when a same-route outbound send exhausted retryable attempts without a
   * definite outcome — the sink must not fall back with a different idempotency key.
   */
  outboundAmbiguousFailure: boolean;
  outboundReceipt?: MarmotTurnOutboundReceipt;
  /** In-flight same-route outbound send shared by concurrent tool calls. */
  outboundInFlight?: Promise<MarmotTurnOutboundReceipt>;
}

const turnDeliveryStorage = new AsyncLocalStorage<MarmotTurnDeliveryState>();

function freezeTurnRoute(route: MarmotTurnRoute): MarmotTurnRoute {
  return Object.freeze({
    channelAccountId: route.channelAccountId,
    marmotAccountIdHex: route.marmotAccountIdHex,
    groupIdHex: route.groupIdHex,
    replyToMessageIdHex: route.replyToMessageIdHex,
    idempotencyKey: route.idempotencyKey,
  });
}

function initialTurnState(route: MarmotTurnRoute): MarmotTurnDeliveryState {
  return {
    route: freezeTurnRoute(route),
    durableOwner: "none",
    outboundDelivered: false,
    outboundAmbiguousFailure: false,
  };
}

/** Run `fn` with turn-scoped delivery coordination bound to `route`. */
export function runInMarmotTurn<T>(route: MarmotTurnRoute, fn: () => T | Promise<T>): Promise<T> {
  return Promise.resolve(turnDeliveryStorage.run(initialTurnState(route), fn));
}

/** Active turn delivery state, if any. */
export function getMarmotTurnDelivery(): MarmotTurnDeliveryState | undefined {
  return turnDeliveryStorage.getStore();
}

export interface MarmotTurnRouteTarget {
  channelAccountId?: string | null;
  marmotAccountIdHex: string;
  groupIdHex: string;
}

/** Whether an outbound target matches the bound inbound turn route. */
export function matchesMarmotTurnRoute(
  state: MarmotTurnDeliveryState,
  target: MarmotTurnRouteTarget,
): boolean {
  const route = state.route;
  if (route.marmotAccountIdHex !== target.marmotAccountIdHex) {
    return false;
  }
  if (route.groupIdHex !== target.groupIdHex) {
    return false;
  }
  const channelAccountId = target.channelAccountId?.trim();
  if (channelAccountId && route.channelAccountId !== channelAccountId) {
    return false;
  }
  return true;
}

/** Resolve the turn idempotency key when inside a turn, else undefined. */
export function resolveTurnIdempotencyKey(state?: MarmotTurnDeliveryState): string | undefined {
  return state?.route.idempotencyKey;
}

/**
 * Record a successful same-route outbound durable send. Repeated calls return
 * false so the adapter can skip duplicate posts while reusing the first receipt.
 */
export function recordTurnOutboundDelivery(
  state: MarmotTurnDeliveryState,
  receipt: MarmotTurnOutboundReceipt,
): boolean {
  if (state.outboundDelivered) {
    return false;
  }
  state.outboundDelivered = true;
  state.durableOwner = "outbound";
  state.outboundReceipt = receipt;
  return true;
}

/** Record a same-route outbound failure; retryable exhaustion blocks sink fallback. */
export function recordTurnOutboundFailure(state: MarmotTurnDeliveryState, retryable: boolean): void {
  if (retryable) {
    state.outboundAmbiguousFailure = true;
    return;
  }
  // A definite non-retryable failure releases the tentative outbound claim so the
  // sink can commit durably with the shared turn idempotency key.
  if (!state.outboundDelivered) {
    state.durableOwner = "none";
  }
}

/** Whether the bound sink must not commit a durable reply for this turn. */
export function shouldSuppressSinkDurableDelivery(state: MarmotTurnDeliveryState): boolean {
  return state.outboundDelivered || state.outboundAmbiguousFailure;
}

/**
 * Fail closed when a same-route outbound send ended ambiguously without a
 * durable receipt. Successful outbound delivery is not an error.
 */
export function assertTurnDurableDeliveryResolved(state: MarmotTurnDeliveryState): void {
  if (state.outboundDelivered) {
    return;
  }
  if (state.outboundAmbiguousFailure) {
    throw new MarmotDispatchAmbiguousDeliveryError();
  }
}

/** Claim sink ownership before committing (no-op when outbound already owns delivery). */
export function claimTurnSinkDelivery(state: MarmotTurnDeliveryState): boolean {
  if (shouldSuppressSinkDurableDelivery(state)) {
    return false;
  }
  if (state.outboundInFlight) {
    return false;
  }
  if (state.durableOwner === "sink") {
    return true;
  }
  if (state.durableOwner === "outbound") {
    return false;
  }
  state.durableOwner = "sink";
  return true;
}

/**
 * Wait for any in-flight same-route outbound send, then claim sink ownership or
 * report suppression. Loops when an outbound send starts in the window after
 * resolution returns but before the sink claim lands.
 */
export async function acquireSinkDeliveryOrSuppress(
  state: MarmotTurnDeliveryState,
): Promise<"suppress" | "proceed"> {
  for (;;) {
    if (state.outboundInFlight) {
      await state.outboundInFlight.catch(() => undefined);
      continue;
    }
    if (shouldSuppressSinkDurableDelivery(state)) {
      return "suppress";
    }
    if (claimTurnSinkDelivery(state)) {
      return "proceed";
    }
    return "suppress";
  }
}

/**
 * Wait for a same-route outbound send to settle and record its terminal outcome
 * before the sink decides whether to commit durably.
 */
export async function awaitTurnOutboundResolution(state: MarmotTurnDeliveryState): Promise<void> {
  if (!state.outboundInFlight) {
    return;
  }
  try {
    await state.outboundInFlight;
  } catch {
    // Terminal failure is recorded on the shared state before the promise rejects.
  }
}

/**
 * Run one same-route outbound send for the turn. Concurrent callers await the
 * first in-flight operation and share its result or failure. Success and
 * retryable/non-retryable failure are recorded before the shared promise settles.
 */
export function runTurnOutboundSendOnce(
  state: MarmotTurnDeliveryState,
  send: () => Promise<MarmotTurnOutboundReceipt>,
  isRetryableError: (error: unknown) => boolean = () => true,
): Promise<MarmotTurnOutboundReceipt> {
  if (state.outboundDelivered && state.outboundReceipt) {
    return Promise.resolve(state.outboundReceipt);
  }
  if (state.durableOwner === "sink") {
    return Promise.reject(new MarmotTurnDurableOwnershipError());
  }
  if (state.outboundInFlight) {
    return state.outboundInFlight;
  }
  // Reserve outbound ownership synchronously before connector I/O so the sink
  // cannot claim in the scheduling gap after awaitTurnOutboundResolution.
  state.durableOwner = "outbound";
  const tracked = (async () => {
    try {
      const receipt = await send();
      recordTurnOutboundDelivery(state, receipt);
      return receipt;
    } catch (error) {
      recordTurnOutboundFailure(state, isRetryableError(error));
      throw error;
    }
  })();
  const inFlight = tracked.finally(() => {
    if (state.outboundInFlight === inFlight) {
      state.outboundInFlight = undefined;
    }
  });
  state.outboundInFlight = inFlight;
  return inFlight;
}
