// Bridge OpenClaw's per-account allow-from list into dm-agent's welcomer
// allowlist, so the connector accepts group welcomes from accounts the operator
// approved in OpenClaw. dm-agent still performs welcomer-based post-join
// accept/decline; this only keeps the two allowlists in sync.
//
// Marmot welcomer ids are account pubkey hex; non-hex OpenClaw allow entries
// (e.g. usernames used by other channels) are ignored.

import type { MarmotAgentControlClient } from "./client.js";

export type AllowlistClient = Pick<
  MarmotAgentControlClient,
  "allowlistList" | "allowlistAdd" | "allowlistRemove"
>;

// Marmot welcomer ids are 32-byte account pubkeys = exactly 64 hex chars.
const MARMOT_ACCOUNT_ID_HEX = /^[0-9a-f]{64}$/;

export function normalizeWelcomerId(entry: string | number): string {
  return String(entry).trim().toLowerCase().replace(/^0x/, "");
}

export interface AllowlistSyncResult {
  added: string[];
  removed: string[];
}

/**
 * Reconcile dm-agent's welcomer allowlist for `accountIdHex` to exactly the
 * hex ids in `desired`. Returns the ids added and removed.
 */
export async function syncAllowlist(
  client: AllowlistClient,
  accountIdHex: string,
  desired: Array<string | number>,
): Promise<AllowlistSyncResult> {
  const want = new Set(
    desired.map(normalizeWelcomerId).filter((id) => MARMOT_ACCOUNT_ID_HEX.test(id)),
  );
  const current = await client.allowlistList(accountIdHex);
  const have = new Set(
    (current.welcomer_account_ids_hex ?? [])
      .map(normalizeWelcomerId)
      .filter((id) => MARMOT_ACCOUNT_ID_HEX.test(id)),
  );

  const added: string[] = [];
  const removed: string[] = [];
  for (const id of want) {
    if (!have.has(id)) {
      await client.allowlistAdd(accountIdHex, id);
      added.push(id);
    }
  }
  for (const id of have) {
    if (!want.has(id)) {
      await client.allowlistRemove(accountIdHex, id);
      removed.push(id);
    }
  }
  return { added, removed };
}
