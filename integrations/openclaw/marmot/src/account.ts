// Marmot account selection. Mirrors the Hermes shim's `_ensure_account_id`:
// when the config does not pin an account and dm-agent hosts exactly one
// local-signing account, select it automatically; otherwise require an explicit
// id. Errors stay privacy-safe (no account ids).

import type { MarmotAgentControlClient } from "./client.js";

export type AccountListClient = Pick<MarmotAgentControlClient, "accountList">;

function normalizeHex(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/, "");
}

/**
 * Resolve the Marmot agent account id hex to use. Validates a preferred id
 * against dm-agent's account list, or auto-selects the sole local-signing
 * account when none is pinned.
 */
export async function resolveSingleAccount(
  client: AccountListClient,
  preferredAccountIdHex?: string | null,
): Promise<string> {
  const response = await client.accountList();
  const accounts = response.accounts ?? [];

  if (preferredAccountIdHex && preferredAccountIdHex.trim() !== "") {
    const wanted = normalizeHex(preferredAccountIdHex);
    const match = accounts.find((account) => normalizeHex(account.account_id_hex) === wanted);
    if (!match) {
      throw new Error("configured Marmot account is not present on dm-agent");
    }
    return match.account_id_hex;
  }

  const signing = accounts.filter((account) => account.local_signing);
  if (signing.length === 1) {
    return signing[0]!.account_id_hex;
  }
  if (signing.length === 0) {
    throw new Error(
      "dm-agent has no local-signing Marmot account; run `dm-agent bootstrap` first",
    );
  }
  throw new Error(
    "dm-agent hosts multiple accounts; set the marmot channel `accountIdHex` (or MARMOT_ACCOUNT_ID_HEX)",
  );
}
