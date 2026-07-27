import { describe, expect, it } from "vitest";

import {
  acquireSinkDeliveryOrSuppress,
  awaitTurnOutboundResolution,
  claimTurnSinkDelivery,
  getMarmotTurnDelivery,
  matchesMarmotTurnRoute,
  recordTurnOutboundDelivery,
  recordTurnOutboundFailure,
  runInMarmotTurn,
  runTurnOutboundSendOnce,
  shouldSuppressSinkDurableDelivery,
  type MarmotTurnRoute,
} from "../src/turn-delivery.js";

const HEX = (b: string) => b.repeat(32);

function sampleRoute(overrides: Partial<MarmotTurnRoute> = {}): MarmotTurnRoute {
  return {
    channelAccountId: "default",
    marmotAccountIdHex: HEX("aa"),
    groupIdHex: HEX("cc"),
    replyToMessageIdHex: HEX("dd"),
    idempotencyKey: "turn-key-1",
    ...overrides,
  };
}

describe("turn delivery coordination", () => {
  it("scopes delivery state to the active async turn only", async () => {
    const outer: MarmotTurnRoute[] = [];
    await runInMarmotTurn(sampleRoute(), async () => {
      outer.push(getMarmotTurnDelivery()!.route);
    });
    expect(getMarmotTurnDelivery()).toBeUndefined();
    expect(outer).toHaveLength(1);
  });

  it("isolates concurrent turns across accounts and groups", async () => {
    const routeA = sampleRoute({ groupIdHex: HEX("01"), idempotencyKey: "a" });
    const routeB = sampleRoute({
      marmotAccountIdHex: HEX("bb"),
      groupIdHex: HEX("02"),
      idempotencyKey: "b",
    });
    const seen: string[] = [];
    await Promise.all([
      runInMarmotTurn(routeA, async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        recordTurnOutboundDelivery(getMarmotTurnDelivery()!, {
          messageIdsHex: [HEX("11")],
        });
        seen.push(getMarmotTurnDelivery()!.route.idempotencyKey);
      }),
      runInMarmotTurn(routeB, async () => {
        recordTurnOutboundDelivery(getMarmotTurnDelivery()!, {
          messageIdsHex: [HEX("22")],
        });
        seen.push(getMarmotTurnDelivery()!.route.idempotencyKey);
      }),
    ]);
    expect(seen.sort()).toEqual(["a", "b"]);
  });

  it("suppresses the sink after a successful same-route outbound delivery", () => {
    const state = {
      route: sampleRoute(),
      durableOwner: "none" as const,
      outboundDelivered: false,
      outboundAmbiguousFailure: false,
    };
    recordTurnOutboundDelivery(state, { messageIdsHex: [HEX("ee")] });
    expect(shouldSuppressSinkDurableDelivery(state)).toBe(true);
    expect(recordTurnOutboundDelivery(state, { messageIdsHex: [HEX("ff")] })).toBe(false);
  });

  it("blocks sink fallback after an ambiguous same-route outbound failure", () => {
    const state = {
      route: sampleRoute(),
      durableOwner: "none" as const,
      outboundDelivered: false,
      outboundAmbiguousFailure: false,
    };
    recordTurnOutboundFailure(state, true);
    expect(shouldSuppressSinkDurableDelivery(state)).toBe(true);
    expect(state.durableOwner).toBe("none");
  });

  it("releases tentative outbound ownership after a definite non-retryable failure", () => {
    const state = {
      route: sampleRoute(),
      durableOwner: "outbound" as const,
      outboundDelivered: false,
      outboundAmbiguousFailure: false,
    };
    recordTurnOutboundFailure(state, false);
    expect(state.durableOwner).toBe("none");
    expect(shouldSuppressSinkDurableDelivery(state)).toBe(false);
    expect(claimTurnSinkDelivery(state)).toBe(true);
  });

  it("claims outbound ownership synchronously before connector I/O", async () => {
    await runInMarmotTurn(sampleRoute(), async () => {
      const state = getMarmotTurnDelivery()!;
      let releaseSend: (() => void) | undefined;
      const sendGate = new Promise<void>((resolve) => {
        releaseSend = resolve;
      });
      const outbound = runTurnOutboundSendOnce(state, async () => {
        await sendGate;
        return { messageIdsHex: [HEX("11")] };
      });
      expect(state.durableOwner).toBe("outbound");
      expect(claimTurnSinkDelivery(state)).toBe(false);
      releaseSend?.();
      await outbound;
    });
  });

  it("suppresses the sink when outbound starts after resolution returns but before claim", async () => {
    await runInMarmotTurn(sampleRoute(), async () => {
      const state = getMarmotTurnDelivery()!;
      let connectorCalls = 0;
      await awaitTurnOutboundResolution(state);
      const outbound = runTurnOutboundSendOnce(state, async () => {
        connectorCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 10));
        return { messageIdsHex: [HEX("11")] };
      });
      const gate = await acquireSinkDeliveryOrSuppress(state);
      await outbound;
      expect(gate).toBe("suppress");
      expect(connectorCalls).toBe(1);
    });
  });

  it("does not match a different group on the same account", () => {
    const state = {
      route: sampleRoute(),
      durableOwner: "none" as const,
      outboundDelivered: false,
      outboundAmbiguousFailure: false,
    };
    expect(
      matchesMarmotTurnRoute(state, {
        marmotAccountIdHex: HEX("aa"),
        groupIdHex: HEX("ff"),
      }),
    ).toBe(false);
  });

  it("stores a frozen route copy isolated from caller mutation", async () => {
    const route = sampleRoute({ idempotencyKey: "original-key" });
    await runInMarmotTurn(route, async () => {
      const stored = getMarmotTurnDelivery()!.route;
      (route as { idempotencyKey: string }).idempotencyKey = "mutated-key";
      expect(stored.idempotencyKey).toBe("original-key");
      expect(Object.isFrozen(stored)).toBe(true);
    });
    expect(route.idempotencyKey).toBe("mutated-key");
  });
});
