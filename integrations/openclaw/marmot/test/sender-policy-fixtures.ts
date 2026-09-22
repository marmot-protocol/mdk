import { createSenderAuthorizer, type MarmotSenderAuthorizer } from "../src/sender-policy.js";

export const TEST_RECEIVING_ACCOUNT = "aa".repeat(32);
export const TEST_ALLOWED_SENDER = "bb".repeat(32);

export function testInboundActor(accountIdHex = TEST_ALLOWED_SENDER, isSelf = false) {
  return { account_id_hex: accountIdHex, display_name: null, is_self: isSelf };
}

export function testAllowlistAuthorizer(
  receivingAccountIdHex = TEST_RECEIVING_ACCOUNT,
  allowedUsers: string[] = [TEST_ALLOWED_SENDER],
): MarmotSenderAuthorizer {
  return createSenderAuthorizer({
    policy: {
      state: "allowlist",
      allowedUsers,
      allowedUserCount: allowedUsers.length,
    },
    receivingAccountIdHex,
  });
}

export function testAllowAllAuthorizer(
  receivingAccountIdHex = TEST_RECEIVING_ACCOUNT,
): MarmotSenderAuthorizer {
  return createSenderAuthorizer({
    policy: { state: "allow_all", allowedUsers: [], allowedUserCount: 0 },
    receivingAccountIdHex,
  });
}

export function testSenderPolicyConfig(allowedUsers: string[] = [TEST_ALLOWED_SENDER]) {
  return { allowedUsers };
}
