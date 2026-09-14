import { describe, expect, it, vi } from "vitest";

import {
  BoundedKeyedAsyncQueue,
  classifyInboundDispatchFailure,
} from "../src/bounded-keyed-async-queue.js";

describe("BoundedKeyedAsyncQueue", () => {
  it("returns explicit admission and sheds once per-key depth is reached", async () => {
    let releaseFirst: (() => void) | undefined;
    const firstStarted = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const ran: string[] = [];
    const pressure = vi.fn();
    const queue = new BoundedKeyedAsyncQueue(2, pressure);

    const first = queue.enqueue("group-a", async () => {
      ran.push("first-start");
      await firstStarted;
      ran.push("first-done");
    });
    const second = queue.enqueue("group-a", async () => {
      ran.push("second");
    });
    const third = queue.enqueue("group-a", async () => {
      ran.push("third");
    });

    await vi.waitFor(() => expect(ran).toContain("first-start"));
    expect(first.outcome).toBe("admitted");
    expect(second.outcome).toBe("admitted");
    expect(third).toEqual({ outcome: "overloaded", reason: "per_group_depth" });
    expect(pressure).toHaveBeenCalledWith({
      reason: "per_group_depth",
      activeGroups: 1,
      maxDepthPerGroup: 2,
      maxTrackedGroups: 256,
    });

    releaseFirst?.();
    await vi.waitFor(() => expect(ran).toEqual(["first-start", "first-done", "second"]));
  });

  it("decrements depth when a queued task rejects", async () => {
    const ran: string[] = [];
    const queue = new BoundedKeyedAsyncQueue(2);

    queue.enqueue("group-a", async () => {
      throw new Error("boom");
    });
    queue.enqueue("group-a", async () => {
      ran.push("after-reject");
    });

    await vi.waitFor(() => expect(ran).toEqual(["after-reject"]));
  });

  it("bounds tracked groups and admits a new group after an active group drains", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pressure = vi.fn();
    const queue = new BoundedKeyedAsyncQueue(2, pressure, 1);

    let drained = false;
    let retriedRan = false;
    const active = queue.enqueue("group-a", async () => {
      await gate;
      drained = true;
    });
    const rejected = queue.enqueue("group-b", async () => undefined);

    expect(active.outcome).toBe("admitted");
    expect(rejected).toEqual({ outcome: "overloaded", reason: "tracked_group_limit" });
    expect(pressure).toHaveBeenLastCalledWith({
      reason: "tracked_group_limit",
      activeGroups: 1,
      maxDepthPerGroup: 2,
      maxTrackedGroups: 1,
    });

    release();
    await vi.waitFor(() => expect(drained).toBe(true));
    const retried = queue.enqueue("group-b", async () => {
      retriedRan = true;
    });
    expect(retried.outcome).toBe("admitted");
    await vi.waitFor(() => expect(retriedRan).toBe(true));
  });

  it("reports the OpenClaw lifecycle mismatch without logging arbitrary error text", async () => {
    const log = vi.fn();
    const queue = new BoundedKeyedAsyncQueue(2, undefined, undefined, log);

    queue.enqueue("group-a", async () => {
      throw new Error(
        "runChannelInboundEvent prepared turns must declare runDispatchLifecycle when creating runDispatch",
      );
    });

    await vi.waitFor(() =>
      expect(log).toHaveBeenCalledWith(
        "marmot: inbound dispatch task failed (class=openclaw_dispatch_lifecycle_contract)",
      ),
    );
  });

  it("does not expose an arbitrary failure message", () => {
    expect(classifyInboundDispatchFailure(new Error("secret conversation contents"))).toBe(
      "error",
    );
  });

  it("classifies beta's agent-scoped session-store requirement without exposing text", () => {
    const error = new Error("potentially sensitive upstream detail");
    error.name = "SessionStoreAgentIdRequiredError";

    expect(classifyInboundDispatchFailure(error)).toBe(
      "openclaw_session_store_agent_id_required",
    );
  });
});
