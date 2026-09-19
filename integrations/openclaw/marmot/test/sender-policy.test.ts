import { describe, expect, it } from "vitest";

import {
  authorizeInboundSender,
  createSenderAuthorizer,
  parseConfigSenderPolicy,
  parseEnvironmentSenderPolicy,
  resolveSenderPolicy,
  senderPolicyErrorCode,
  senderPolicyIsReady,
  MARMOT_SENDER_POLICY_INVALID,
  MARMOT_SENDER_POLICY_MISSING,
} from "../src/sender-policy.js";

const HEX32 = (b: string) => b.repeat(32);
const OWNER = HEX32("aa");
const SENDER = HEX32("bb");
const OTHER = HEX32("cc");

function actor(id: string, isSelf = false) {
  return { account_id_hex: id, is_self: isSelf };
}

function input(overrides: {
  receiving?: string;
  mapped?: string;
  sender?: { account_id_hex?: unknown; is_self?: unknown } | null;
} = {}) {
  return {
    receivingAccountIdHex: overrides.receiving ?? OWNER,
    mappedSenderAccountIdHex: overrides.mapped ?? SENDER,
    sender: overrides.sender === undefined ? actor(SENDER) : overrides.sender,
  };
}

describe("parseConfigSenderPolicy", () => {
  it("treats absent and empty lists without allowAll as missing", () => {
    expect(parseConfigSenderPolicy(undefined).state).toBe("missing");
    expect(parseConfigSenderPolicy({}).state).toBe("missing");
    expect(parseConfigSenderPolicy({ allowedUsers: [] }).state).toBe("missing");
    expect(parseConfigSenderPolicy({ allowedUsers: [], allowAll: false }).state).toBe("missing");
  });

  it("accepts exact hex, trims surrounding whitespace, lowercases, and deduplicates", () => {
    const parsed = parseConfigSenderPolicy({
      allowedUsers: [` ${SENDER.toUpperCase()} `, SENDER, ` ${SENDER} `],
    });
    expect(parsed).toEqual({
      state: "allowlist",
      allowedUsers: [SENDER],
      allowedUserCount: 1,
    });
  });

  it("lets explicit allowAll win over a valid list", () => {
    expect(parseConfigSenderPolicy({ allowedUsers: [SENDER], allowAll: true })).toMatchObject({
      state: "allow_all",
      allowedUsers: [SENDER],
      allowedUserCount: 1,
    });
  });

  it("rejects wrong types, unknown fields, invalid booleans, and one bad member", () => {
    expect(parseConfigSenderPolicy(null).state).toBe("invalid");
    expect(parseConfigSenderPolicy([]).state).toBe("invalid");
    expect(parseConfigSenderPolicy("allow").state).toBe("invalid");
    expect(parseConfigSenderPolicy({ allowedUsers: [SENDER], extra: true })).toMatchObject({
      state: "invalid",
      reason: "unknown_field",
    });
    expect(parseConfigSenderPolicy({ allowAll: "true" })).toMatchObject({
      state: "invalid",
      reason: "invalid_boolean",
    });
    expect(parseConfigSenderPolicy({ allowedUsers: [SENDER, "npub1abc"] })).toMatchObject({
      state: "invalid",
      reason: "invalid_entry",
    });
    expect(parseConfigSenderPolicy({ allowedUsers: [SENDER, 12] }).state).toBe("invalid");
    expect(parseConfigSenderPolicy({ allowedUsers: ["0x" + SENDER] }).state).toBe("invalid");
    expect(parseConfigSenderPolicy({ allowedUsers: [SENDER.slice(0, 32)] }).state).toBe("invalid");
    expect(parseConfigSenderPolicy({ allowedUsers: [`*${SENDER}`] }).state).toBe("invalid");
    expect(parseConfigSenderPolicy({ allowedUsers: [SENDER], allowAll: true, extra: 1 }).state).toBe(
      "invalid",
    );
  });
});

describe("parseEnvironmentSenderPolicy", () => {
  it("is missing when both variables are unset", () => {
    expect(parseEnvironmentSenderPolicy({}).state).toBe("missing");
  });

  it("parses comma-separated hex and documented boolean forms", () => {
    expect(
      parseEnvironmentSenderPolicy({
        MARMOT_ALLOWED_USERS: `${SENDER.toUpperCase()}, ${OTHER}`,
        MARMOT_ALLOW_ALL_USERS: "false",
      }),
    ).toEqual({
      state: "allowlist",
      allowedUsers: [SENDER, OTHER],
      allowedUserCount: 2,
    });
    expect(parseEnvironmentSenderPolicy({ MARMOT_ALLOW_ALL_USERS: "YES" }).state).toBe("allow_all");
    expect(parseEnvironmentSenderPolicy({ MARMOT_ALLOW_ALL_USERS: "0" }).state).toBe("missing");
  });

  it("treats blank or malformed explicitly supplied flags and entries as invalid", () => {
    expect(parseEnvironmentSenderPolicy({ MARMOT_ALLOW_ALL_USERS: "" }).state).toBe("invalid");
    expect(parseEnvironmentSenderPolicy({ MARMOT_ALLOW_ALL_USERS: "maybe" }).state).toBe("invalid");
    expect(parseEnvironmentSenderPolicy({ MARMOT_ALLOWED_USERS: "not-hex" }).state).toBe("invalid");
    expect(
      parseEnvironmentSenderPolicy({
        MARMOT_ALLOWED_USERS: SENDER,
        MARMOT_ALLOW_ALL_USERS: "truee",
      }).state,
    ).toBe("invalid");
  });
});

describe("resolveSenderPolicy", () => {
  it("lets an explicit config senderPolicy replace the entire environment atomically", () => {
    const env = {
      MARMOT_ALLOWED_USERS: OTHER,
      MARMOT_ALLOW_ALL_USERS: "true",
    };
    expect(resolveSenderPolicy({ senderPolicy: { allowedUsers: [SENDER] } }, env)).toEqual({
      state: "allowlist",
      allowedUsers: [SENDER],
      allowedUserCount: 1,
    });
    expect(resolveSenderPolicy({ senderPolicy: {} }, env).state).toBe("missing");
    expect(resolveSenderPolicy({ senderPolicy: null }, env).state).toBe("invalid");
    expect(resolveSenderPolicy({ senderPolicy: { allowedUsers: ["bad"] } }, env).state).toBe(
      "invalid",
    );
    expect(resolveSenderPolicy({}, env).state).toBe("allow_all");
    expect(resolveSenderPolicy(undefined, env).state).toBe("allow_all");
  });

  it("does not merge sibling-account config into the selected account", () => {
    expect(
      resolveSenderPolicy(
        {},
        { MARMOT_ALLOWED_USERS: SENDER },
      ),
    ).toMatchObject({ state: "allowlist", allowedUsers: [SENDER] });
    expect(
      resolveSenderPolicy({ senderPolicy: { allowedUsers: [OWNER] } }, { MARMOT_ALLOWED_USERS: SENDER }),
    ).toMatchObject({ state: "allowlist", allowedUsers: [OWNER] });
  });
});

describe("createSenderAuthorizer", () => {
  it("allows exact listed senders and denies everyone else, including welcomer-only ids", () => {
    const authorizer = createSenderAuthorizer({
      policy: parseConfigSenderPolicy({ allowedUsers: [SENDER] }),
      receivingAccountIdHex: OWNER,
    });
    expect(authorizer.authorize(input())).toEqual({ outcome: "allow", reason: "allowlist" });
    expect(authorizer.authorize(input({ mapped: OTHER, sender: actor(OTHER) }))).toEqual({
      outcome: "deny",
      reason: "sender_not_allowed",
    });
  });

  it("allows any well-formed non-self sender under explicit allow-all", () => {
    const authorizer = createSenderAuthorizer({
      policy: parseConfigSenderPolicy({ allowAll: true }),
      receivingAccountIdHex: OWNER,
    });
    expect(authorizer.authorize(input({ mapped: OTHER, sender: actor(OTHER) }))).toEqual({
      outcome: "allow",
      reason: "allow_all",
    });
  });

  it("rejects identity and lifecycle failures under allowlist and allow-all", () => {
    for (const policy of [
      parseConfigSenderPolicy({ allowedUsers: [SENDER] }),
      parseConfigSenderPolicy({ allowAll: true }),
    ]) {
      const authorizer = createSenderAuthorizer({
        policy,
        receivingAccountIdHex: OWNER,
      });
      expect(authorizer.authorize(input({ sender: null }))).toEqual({
        outcome: "deny",
        reason: "missing_actor",
      });
      expect(authorizer.authorize(input({ sender: { account_id_hex: SENDER } }))).toEqual({
        outcome: "deny",
        reason: "missing_self_flag",
      });
      expect(authorizer.authorize(input({ sender: actor(` ${SENDER} `) }))).toEqual({
        outcome: "deny",
        reason: "malformed_sender",
      });
      expect(authorizer.authorize(input({ sender: actor("0x" + SENDER) }))).toEqual({
        outcome: "deny",
        reason: "malformed_sender",
      });
      expect(authorizer.authorize(input({ mapped: OTHER, sender: actor(SENDER) }))).toEqual({
        outcome: "deny",
        reason: "inconsistent_sender",
      });
      expect(authorizer.authorize(input({ sender: actor(SENDER, true) }))).toEqual({
        outcome: "deny",
        reason: "self_sender",
      });
      expect(
        authorizer.authorize(input({ receiving: OWNER, mapped: OWNER, sender: actor(OWNER) })),
      ).toEqual({ outcome: "deny", reason: "self_id_equality" });
      expect(authorizer.authorize(input({ receiving: OTHER }))).toEqual({
        outcome: "deny",
        reason: "receiving_account_mismatch",
      });
      authorizer.setLifecycle("stopped");
      expect(authorizer.authorize(input())).toEqual({
        outcome: "deny",
        reason: "lifecycle_stopped",
      });
      authorizer.setLifecycle("active");
    }
  });

  it("stays unused until the receiving account is bound", () => {
    const authorizer = createSenderAuthorizer({
      policy: parseConfigSenderPolicy({ allowAll: true }),
    });
    expect(authorizer.authorize(input())).toEqual({
      outcome: "deny",
      reason: "lifecycle_unbound",
    });
    expect(authorizer.bindReceivingAccount(OWNER)).toBe(true);
    expect(authorizer.authorize(input())).toEqual({ outcome: "allow", reason: "allow_all" });
  });

  it("reactivates a stopped authorizer on a valid rebind and keeps replaced/invalid terminal", () => {
    const authorizer = createSenderAuthorizer({
      policy: parseConfigSenderPolicy({ allowedUsers: [SENDER] }),
      receivingAccountIdHex: OWNER,
    });
    expect(authorizer.authorize(input())).toEqual({ outcome: "allow", reason: "allowlist" });
    authorizer.setLifecycle("stopped");
    expect(authorizer.authorize(input())).toEqual({
      outcome: "deny",
      reason: "lifecycle_stopped",
    });
    expect(authorizer.bindReceivingAccount(OWNER)).toBe(true);
    expect(authorizer.lifecycle()).toBe("active");
    expect(authorizer.authorize(input())).toEqual({ outcome: "allow", reason: "allowlist" });
    expect(authorizer.authorize(input({ mapped: OTHER, sender: actor(OTHER) }))).toEqual({
      outcome: "deny",
      reason: "sender_not_allowed",
    });

    authorizer.setLifecycle("replaced");
    expect(authorizer.bindReceivingAccount(OWNER)).toBe(true);
    expect(authorizer.lifecycle()).toBe("replaced");
    expect(authorizer.authorize(input())).toEqual({
      outcome: "deny",
      reason: "lifecycle_replaced",
    });

    const invalid = createSenderAuthorizer({
      policy: parseConfigSenderPolicy({ allowedUsers: ["nope"] }),
      receivingAccountIdHex: OWNER,
    });
    expect(invalid.lifecycle()).toBe("invalid");
    expect(invalid.bindReceivingAccount(OWNER)).toBe(true);
    expect(invalid.lifecycle()).toBe("invalid");
    expect(invalid.authorize(input())).toEqual({
      outcome: "deny",
      reason: "lifecycle_invalid",
    });
  });

  it("does not authorize when the common authorizer is missing", () => {
    expect(authorizeInboundSender(null, input())).toEqual({
      outcome: "deny",
      reason: "missing_authorizer",
    });
    expect(authorizeInboundSender(undefined, input())).toEqual({
      outcome: "deny",
      reason: "missing_authorizer",
    });
  });

  it("keeps readiness labels and error codes aggregate-only", () => {
    expect(senderPolicyIsReady("allowlist")).toBe(true);
    expect(senderPolicyIsReady("allow_all")).toBe(true);
    expect(senderPolicyIsReady("missing")).toBe(false);
    expect(senderPolicyErrorCode("pending")).toBeNull();
    expect(senderPolicyErrorCode("missing")).toBe(MARMOT_SENDER_POLICY_MISSING);
    expect(senderPolicyErrorCode("invalid")).toBe(MARMOT_SENDER_POLICY_INVALID);
    expect(JSON.stringify(parseConfigSenderPolicy({ allowedUsers: [SENDER] }))).toContain(SENDER);
    expect(senderPolicyErrorCode("allowlist")).toBeNull();
  });
});
