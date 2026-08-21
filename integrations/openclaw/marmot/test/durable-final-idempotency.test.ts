import { describe, expect, it } from "vitest";

import { deriveDurableFinalIdempotency } from "../src/durable-final-idempotency.js";

describe("deriveDurableFinalIdempotency", () => {
  it("matches the normative durable-final vector", () => {
    expect(
      deriveDurableFinalIdempotency({
        accountIdHex: "aa",
        groupIdHex: "bb",
        text: "pong",
        replyToMessageIdHex: null,
        sessionBinding: "agent:marmot",
        turnBinding: "cc",
      }),
    ).toEqual({
      replyAnchor: null,
      contentFingerprint: "85876ccb1fb1fb3e67b5e5375950fc5dad2e32928c84017b17df891a5c0a186d",
      idempotencyKey:
        "marmot-final-v1:59e4466f34ab5882182ee28aa2b2c63be121c167513460c721b7d3e1b29c07c1",
    });
  });

  it("fails closed on missing durable host identity", () => {
    expect(() =>
      deriveDurableFinalIdempotency({
        accountIdHex: "aa",
        groupIdHex: "bb",
        text: "pong",
        replyToMessageIdHex: null,
        sessionBinding: "agent:marmot",
        turnBinding: "",
      }),
    ).toThrow("turnBinding must not be empty");
  });
});
