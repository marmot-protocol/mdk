/**
 * dm-agent control-plane smoke test (standalone; NOT part of the build).
 *
 * Exercises the `marmot.agent-control.v1` socket end-to-end through
 * `MarmotAgentControlClient`: account_list, group_info, send_final (capturing
 * the durable id), delete_message of that id, optional send_media, and a brief
 * subscribe_inbound that prints kinds + counts only. Prints clear PASS/FAIL per
 * step and never logs payloads or full ids — only short hashes.
 *
 * Usage (this file is excluded from tsconfig, so it is not type-checked/built):
 *
 *   # Preferred — run the TypeScript directly with tsx:
 *   MARMOT_AGENT_SOCKET=/path/to/dm-agent.sock \
 *     npx tsx integrations/openclaw/marmot/scripts/dm-agent-smoketest.ts
 *
 *   # Or, after `pnpm build`, with a modern Node (>= 22.18 strips TS natively):
 *   pnpm build && MARMOT_AGENT_SOCKET=/path/to/dm-agent.sock \
 *     node integrations/openclaw/marmot/scripts/dm-agent-smoketest.ts
 *
 * Env:
 *   MARMOT_AGENT_SOCKET     (required) path to the dm-agent control Unix socket
 *   MARMOT_AGENT_TOKEN      (optional) auth token, if the connector requires one
 *   MARMOT_ACCOUNT_ID_HEX   (optional) account hex; defaults to the sole local-signing account
 *   MARMOT_GROUP_ID_HEX     (optional) group hex; required for the send/delete/media steps
 *   MARMOT_TEST_IMAGE       (optional) local image path; enables the send_media step
 *   MARMOT_INBOUND_SECONDS  (optional) how long to listen for inbound events (default 5)
 *
 * The client import resolves to the built JS under dist (works with plain node
 * after `pnpm build`) and to the source under tsx (which maps .js -> .ts).
 */

import { basename } from "node:path";

import {
  AgentControlError,
  MarmotAgentControlClient,
  type AgentControlMediaRef,
  type MarmotAgentControlClientOptions,
} from "../dist/src/client.js";

/** Short, privacy-safe hash of an id-like string (first 8 hex chars of a fold). */
function shortHash(value: string | null | undefined): string {
  const text = String(value ?? "");
  if (text.length === 0) {
    return "<empty>";
  }
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0").slice(0, 8);
}

let passCount = 0;
let failCount = 0;

function pass(step: string, detail = ""): void {
  passCount += 1;
  console.log(`PASS  ${step}${detail ? ` — ${detail}` : ""}`);
}

function fail(step: string, err: unknown): void {
  failCount += 1;
  const message =
    err instanceof AgentControlError
      ? `${err.code}: ${err.message}`
      : err instanceof Error
        ? err.message
        : String(err);
  console.log(`FAIL  ${step} — ${message}`);
}

function skip(step: string, reason: string): void {
  console.log(`SKIP  ${step} — ${reason}`);
}

async function main(): Promise<void> {
  const socketPath = process.env.MARMOT_AGENT_SOCKET;
  if (!socketPath) {
    console.error("MARMOT_AGENT_SOCKET is required (path to the dm-agent control socket).");
    process.exitCode = 2;
    return;
  }

  const options: MarmotAgentControlClientOptions = {
    socketPath,
    authToken: process.env.MARMOT_AGENT_TOKEN,
  };
  const client = new MarmotAgentControlClient(options);

  // 1) account_list -----------------------------------------------------------
  let accountIdHex = process.env.MARMOT_ACCOUNT_ID_HEX ?? null;
  try {
    const accounts = await client.accountList();
    const signing = accounts.accounts.filter((a) => a.local_signing);
    pass(
      "account_list",
      `accounts=${accounts.accounts.length} local_signing=${signing.length}`,
    );
    if (!accountIdHex) {
      accountIdHex = signing[0]?.account_id_hex ?? accounts.accounts[0]?.account_id_hex ?? null;
    }
    if (accountIdHex) {
      console.log(`      using account=${shortHash(accountIdHex)}`);
    }
  } catch (err) {
    fail("account_list", err);
  }

  const groupIdHex = process.env.MARMOT_GROUP_ID_HEX ?? null;

  // 2) group_info -------------------------------------------------------------
  if (accountIdHex && groupIdHex) {
    try {
      const info = await client.groupInfo(accountIdHex, groupIdHex);
      pass(
        "group_info",
        `members=${info.member_count} is_direct=${info.is_direct} group=${shortHash(groupIdHex)}`,
      );
    } catch (err) {
      fail("group_info", err);
    }
  } else {
    skip("group_info", "MARMOT_GROUP_ID_HEX (and an account) required");
  }

  // 3) send_final + 4) delete_message ----------------------------------------
  let sentMessageIdHex: string | null = null;
  if (accountIdHex && groupIdHex) {
    try {
      const sent = await client.sendFinal(
        accountIdHex,
        groupIdHex,
        "dm-agent smoke test (this message will be deleted)",
      );
      sentMessageIdHex = sent.message_ids_hex[0] ?? null;
      pass(
        "send_final",
        `ids=${sent.message_ids_hex.length} first=${shortHash(sentMessageIdHex)}`,
      );
    } catch (err) {
      fail("send_final", err);
    }

    if (sentMessageIdHex) {
      try {
        const deleted = await client.deleteMessage(accountIdHex, groupIdHex, sentMessageIdHex);
        pass(
          "delete_message",
          `target=${shortHash(sentMessageIdHex)} ids=${deleted.message_ids_hex.length}`,
        );
      } catch (err) {
        fail("delete_message", err);
      }
    } else {
      skip("delete_message", "send_final produced no message id");
    }
  } else {
    skip("send_final", "MARMOT_GROUP_ID_HEX (and an account) required");
    skip("delete_message", "MARMOT_GROUP_ID_HEX (and an account) required");
  }

  // 5) send_media (optional) --------------------------------------------------
  const imagePath = process.env.MARMOT_TEST_IMAGE ?? null;
  if (accountIdHex && groupIdHex && imagePath) {
    try {
      const fileName = basename(imagePath) || "attachment";
      const ext = fileName.toLowerCase();
      const mediaType = ext.endsWith(".png")
        ? "image/png"
        : ext.endsWith(".gif")
          ? "image/gif"
          : ext.endsWith(".webp")
            ? "image/webp"
            : "image/jpeg";
      const sent = await client.sendMedia(
        accountIdHex,
        groupIdHex,
        [{ path: imagePath, media_type: mediaType, file_name: fileName }],
        "dm-agent smoke test attachment",
      );
      pass("send_media", `ids=${sent.message_ids_hex.length} mime=${mediaType}`);
    } catch (err) {
      fail("send_media", err);
    }
  } else {
    skip("send_media", imagePath ? "group/account required" : "MARMOT_TEST_IMAGE not set");
  }

  // 6) subscribe_inbound (print kinds + counts only) --------------------------
  const listenSeconds = Number(process.env.MARMOT_INBOUND_SECONDS ?? "5");
  try {
    const controller = new AbortController();
    const kinds = new Map<string, number>();
    let mediaRefCount = 0;
    let firstEvents = 0;
    let listenWindowAborted = false;
    const timer = setTimeout(() => {
      listenWindowAborted = true;
      controller.abort();
    }, Math.max(0, listenSeconds) * 1000);

    let ready = false;
    const iter = client.subscribeInbound(
      { accountIdHex, groupIdHex },
      controller.signal,
      { onReady: () => (ready = true) },
    );
    try {
      for await (const event of iter) {
        kinds.set(event.type, (kinds.get(event.type) ?? 0) + 1);
        if (event.type === "inbound_message") {
          const media = (event as { media?: AgentControlMediaRef[] }).media;
          mediaRefCount += media?.length ?? 0;
        }
        firstEvents += 1;
        if (firstEvents <= 5) {
          console.log(`      inbound event #${firstEvents}: kind=${event.type}`);
        }
      }
    } finally {
      clearTimeout(timer);
    }

    const summary = [...kinds.entries()].map(([k, n]) => `${k}=${n}`).join(" ");
    pass(
      "subscribe_inbound",
      `ready=${ready} events=${firstEvents} media_refs=${mediaRefCount}${summary ? ` [${summary}]` : ""}`,
    );
  } catch (err) {
    // An intentional abort (the listen-window timer firing) tears the socket
    // down and surfaces as a read error; that is the expected end of the listen
    // window, not a failure. A `socket_io` error before the timer fired is a
    // genuine transport failure and must be reported.
    if (listenWindowAborted && err instanceof AgentControlError && err.code === "socket_io") {
      pass("subscribe_inbound", `closed after ~${listenSeconds}s`);
    } else {
      fail("subscribe_inbound", err);
    }
  }

  console.log("");
  console.log(`SMOKETEST RESULT: ${passCount} passed, ${failCount} failed`);
  process.exitCode = failCount > 0 ? 1 : 0;
}

main().catch((err) => {
  console.error("smoketest crashed:", err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
