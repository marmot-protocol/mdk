// Bridge OpenClaw's per-account allow-from list into wn-agent's welcomer
// allowlist, so the connector accepts group welcomes from accounts the operator
// approved in OpenClaw. wn-agent still performs welcomer-based post-join
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

function welcomerIdSet(entries: Array<string | number>): Set<string> {
  return new Set(
    entries.map(normalizeWelcomerId).filter((id) => MARMOT_ACCOUNT_ID_HEX.test(id)),
  );
}

export interface AllowlistSyncResult {
  /** Ids a successful `allowlist_add` confirmed. */
  added: string[];
  /** Ids a successful `allowlist_remove` confirmed. */
  removed: string[];
  /** Ids whose `allowlist_add` threw; they are not authorized. */
  failedAdds: string[];
  /** Ids whose `allowlist_remove` threw; they are still authorized. */
  failedRemovals: string[];
  /**
   * True only when the allowlist was read back after reconciliation and the
   * effective set equalled the desired set. False means the caller must treat
   * the allowlist as unreconciled, including when the read-back itself failed.
   */
  verified: boolean;
}

async function effectiveWelcomers(
  client: AllowlistClient,
  accountIdHex: string,
): Promise<Set<string>> {
  const response = await client.allowlistList(accountIdHex);
  return welcomerIdSet(response.welcomer_account_ids_hex ?? []);
}

/**
 * Reconcile wn-agent's welcomer allowlist for `accountIdHex` to exactly the hex
 * ids in `desired` using best-effort reconciliation:
 *
 * - revocations run first, so a security-critical shrink never waits behind a
 *   grow that may fail;
 * - every step is attempted even when an earlier one throws;
 * - `added`/`removed` list only confirmed changes, failures land in
 *   `failedAdds`/`failedRemovals`;
 * - the effective set is read back and only an exact match sets `verified`.
 *
 * `wn-agent` exposes no atomic replace, so reconciliation is still a sequence of
 * single-entry mutations: a failed removal leaves that entry authorized until
 * a later successful sync. A caller that sees `verified: false` knows the
 * authoritative set diverges but cannot assume any particular intermediate
 * state. The read-back is also account-scoped, not connector-scoped, so a
 * concurrent writer on a shared account reads as divergence.
 *
 * `signal` stops the sequence at the next mutation boundary, for a caller whose
 * desired set has been superseded. Stopping early never authorizes an entry the
 * caller did not ask for, but it can leave a revocation pending — the same
 * exposure as a failed removal. That is bounded rather than open-ended: a
 * caller only aborts because a replacement is taking over, and the replacement
 * reconciles the current desired set against a fresh read. The single request
 * already dispatched cannot be recalled, so an aborted sync still owes its
 * caller one in-flight mutation. `verified` is false whenever the sequence
 * stopped early.
 */
export async function syncAllowlist(
  client: AllowlistClient,
  accountIdHex: string,
  desired: Array<string | number>,
  signal?: AbortSignal,
): Promise<AllowlistSyncResult> {
  const want = welcomerIdSet(desired);
  if (signal?.aborted) {
    return { added: [], removed: [], failedAdds: [], failedRemovals: [], verified: false };
  }
  // Nothing has been mutated yet, so an unreadable current set is a plain throw.
  const have = await effectiveWelcomers(client, accountIdHex);

  const result: AllowlistSyncResult = {
    added: [],
    removed: [],
    failedAdds: [],
    failedRemovals: [],
    verified: false,
  };

  for (const id of have) {
    if (want.has(id)) {
      continue;
    }
    if (signal?.aborted) {
      return result;
    }
    try {
      await client.allowlistRemove(accountIdHex, id);
      result.removed.push(id);
    } catch {
      result.failedRemovals.push(id);
    }
  }
  for (const id of want) {
    if (have.has(id)) {
      continue;
    }
    if (signal?.aborted) {
      return result;
    }
    try {
      await client.allowlistAdd(accountIdHex, id);
      result.added.push(id);
    } catch {
      result.failedAdds.push(id);
    }
  }

  if (signal?.aborted) {
    return result;
  }

  try {
    const effective = await effectiveWelcomers(client, accountIdHex);
    result.verified = effective.size === want.size && [...want].every((id) => effective.has(id));
  } catch {
    result.verified = false;
  }
  return result;
}
