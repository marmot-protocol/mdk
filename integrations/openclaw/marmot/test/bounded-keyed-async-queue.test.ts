import { describe, expect, it, vi } from "vitest";

import {
  BoundedKeyedAsyncQueue,
  classifyInboundDispatchFailure,
} from "../src/bounded-keyed-async-queue.js";

describe("BoundedKeyedAsyncQueue", () => {
  it("sheds incoming turns once per-key depth is reached", async () => {
    let releaseFirst: (() => void) | undefined;
    const firstStarted = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const ran: string[] = [];
    const shed = vi.fn();
    const queue = new BoundedKeyedAsyncQueue(2, shed);

    queue.enqueue("group-a", async () => {
      ran.push("first-start");
      await firstStarted;
      ran.push("first-done");
    });
    queue.enqueue("group-a", async () => {
      ran.push("second");
    });
    queue.enqueue("group-a", async () => {
      ran.push("third");
    });

    await vi.waitFor(() => expect(ran).toContain("first-start"));
    expect(shed).toHaveBeenCalledWith("marmot: inbound queue depth exceeded; shedding turn");

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

  it("reports the OpenClaw lifecycle mismatch without logging arbitrary error text", async () => {
    const log = vi.fn();
    const queue = new BoundedKeyedAsyncQueue(2, log);

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
});
