import { describe, expect, it, vi } from "vitest";

import { AgentControlError } from "../src/client.js";
import { waitForGroupReadiness } from "../src/readiness.js";

const HEX = "a".repeat(32);

function groupInfoStub() {
  return {
    type: "group_info" as const,
    account_id_hex: HEX,
    group_id_hex: HEX,
    member_count: 2,
    is_direct: true,
    subject: null,
  };
}

describe("waitForGroupReadiness", () => {
  it("returns ready with group info on the first successful group_info", async () => {
    const client = {
      groupInfo: vi.fn(async () => groupInfoStub()),
    };
    await expect(
      waitForGroupReadiness({
        client,
        accountIdHex: HEX,
        groupIdHex: HEX,
      }),
    ).resolves.toEqual({ status: "ready", groupInfo: groupInfoStub() });
    expect(client.groupInfo).toHaveBeenCalledTimes(1);
  });

  it("retries transient failures then succeeds once", async () => {
    let calls = 0;
    const client = {
      groupInfo: vi.fn(async () => {
        calls += 1;
        if (calls === 1) {
          throw new AgentControlError("temporary", { retryable: true });
        }
        return groupInfoStub();
      }),
    };
    await expect(
      waitForGroupReadiness({
        client,
        accountIdHex: HEX,
        groupIdHex: HEX,
        backoffMs: [1],
        maxAttempts: 3,
      }),
    ).resolves.toMatchObject({ status: "ready" });
    expect(client.groupInfo).toHaveBeenCalledTimes(2);
  });

  it("stops after bounded attempts", async () => {
    const client = {
      groupInfo: vi.fn(async () => {
        throw new AgentControlError("temporary", { retryable: true });
      }),
    };
    await expect(
      waitForGroupReadiness({
        client,
        accountIdHex: HEX,
        groupIdHex: HEX,
        backoffMs: [1],
        maxAttempts: 2,
      }),
    ).resolves.toEqual({ status: "not_ready", reason: "timeout" });
    expect(client.groupInfo).toHaveBeenCalledTimes(2);
  });

  it("stops retrying after a retryable failure is followed by a non-retryable error", async () => {
    let calls = 0;
    const client = {
      groupInfo: vi.fn(async () => {
        calls += 1;
        if (calls === 1) {
          throw new AgentControlError("temporary", { retryable: true });
        }
        throw new AgentControlError("permanent", { retryable: false });
      }),
    };
    await expect(
      waitForGroupReadiness({
        client,
        accountIdHex: HEX,
        groupIdHex: HEX,
        backoffMs: [1],
        maxAttempts: 4,
      }),
    ).resolves.toEqual({ status: "not_ready", reason: "non_retryable" });
    expect(client.groupInfo).toHaveBeenCalledTimes(2);
  });
});
