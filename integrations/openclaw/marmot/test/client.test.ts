import { createServer, type Server, type Socket } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  AgentControlError,
  MarmotAgentControlClient,
  normalizeHex,
} from "../src/client.js";

const PROTOCOL = "marmot.agent-control.v1";
const HEX32 = (b: string) => b.repeat(32);

function send(socket: Socket, id: unknown, payload: Record<string, unknown>): void {
  socket.write(`${JSON.stringify({ marmot_agent_control: PROTOCOL, id, ...payload })}\n`);
}

/** Minimal in-memory dm-agent control socket for exercising the client. */
function handleRequest(socket: Socket, req: Record<string, unknown>): void {
  const id = req.id;
  switch (req.type) {
    case "account_list":
      send(socket, id, {
        type: "account_list",
        accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
      });
      break;
    case "send_final":
      // Echo back the idempotency_key (when present) so a test can assert the
      // client forwarded it; real dm-agent never returns it.
      send(socket, id, {
        type: "final_sent",
        message_ids_hex: [HEX32("ab")],
        echoed_idempotency_key: req.idempotency_key ?? null,
      });
      break;
    case "delete_message":
      send(socket, id, { type: "final_sent", message_ids_hex: [HEX32("de")] });
      break;
    case "send_media":
      send(socket, id, { type: "final_sent", message_ids_hex: [HEX32("11")] });
      break;
    case "download_media":
      send(socket, id, {
        type: "media_downloaded",
        path: "/tmp/marmot-media/abc/a.png",
        media_type: "image/png",
        file_name: "a.png",
        size_bytes: 4,
      });
      break;
    case "stream_begin":
      send(socket, id, {
        type: "stream_begun",
        stream_id_hex: HEX32("ee"),
        start_message_id_hex: HEX32("ff"),
        quic_candidates: [],
      });
      break;
    case "group_info":
      send(socket, id, {
        type: "group_info",
        account_id_hex: req.account_id_hex ?? HEX32("aa"),
        group_id_hex: req.group_id_hex ?? HEX32("cc"),
        member_count: 2,
        is_direct: true,
        subject: null,
      });
      break;
    case "explode":
      send(socket, id, { type: "error", code: "bad_request", message: "nope" });
      break;
    case "wrong_id":
      send(socket, "some-other-id", { type: "ack" });
      break;
    case "wrong_proto":
      socket.write(`${JSON.stringify({ marmot_agent_control: "nope", id, type: "ack" })}\n`);
      break;
    case "subscribe_inbound":
      send(socket, id, { type: "ack" });
      send(socket, id, {
        type: "inbound_message",
        account_id_hex: req.account_id_hex ?? HEX32("aa"),
        group_id_hex: HEX32("cc"),
        message_id_hex: HEX32("dd"),
        sender_account_id_hex: HEX32("bb"),
        text: "hello agent",
      });
      send(socket, id, {
        type: "resync_required",
        account_id_hex: null,
        group_id_hex: null,
        dropped_events: 3,
      });
      socket.end();
      break;
    default:
      send(socket, id, { type: "error", code: "unknown", message: "unknown type" });
  }
}

function startServer(socketPath: string, responseDelayMs = 0): Promise<Server> {
  const server = createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      let index = buffer.indexOf(0x0a);
      while (index !== -1) {
        const line = buffer.subarray(0, index);
        buffer = buffer.subarray(index + 1);
        if (line.length > 0) {
          const req = JSON.parse(line.toString("utf8"));
          if (responseDelayMs > 0) {
            setTimeout(() => handleRequest(socket, req), responseDelayMs);
          } else {
            handleRequest(socket, req);
          }
        }
        index = buffer.indexOf(0x0a);
      }
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve(server));
  });
}

describe("MarmotAgentControlClient", () => {
  let dir: string;
  let socketPath: string;
  let server: Server;
  let client: MarmotAgentControlClient;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "oc-marmot-"));
    socketPath = join(dir, "a.sock");
    server = await startServer(socketPath);
    client = new MarmotAgentControlClient({ socketPath, requestTimeoutMs: 2000 });
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  });

  it("round-trips a typed request", async () => {
    const res = await client.accountList();
    expect(res.accounts).toHaveLength(1);
    expect(res.accounts[0]?.label).toBe("agent");
  });

  it("returns durable message ids from send_final", async () => {
    const res = await client.sendFinal(HEX32("aa"), HEX32("cc"), "done");
    expect(res.message_ids_hex).toEqual([HEX32("ab")]);
  });

  it("forwards an idempotency_key on send_final when supplied, and omits it otherwise", async () => {
    const withKey = (await client.sendFinal(
      HEX32("aa"),
      HEX32("cc"),
      "done",
      null,
      "retry-key-1",
    )) as unknown as { echoed_idempotency_key?: string | null };
    expect(withKey.echoed_idempotency_key).toBe("retry-key-1");

    const withoutKey = (await client.sendFinal(
      HEX32("aa"),
      HEX32("cc"),
      "done",
    )) as unknown as { echoed_idempotency_key?: string | null };
    expect(withoutKey.echoed_idempotency_key).toBeNull();
  });

  it("deletes a message and returns the deletion event ids", async () => {
    const res = await client.deleteMessage(HEX32("aa"), HEX32("cc"), HEX32("dd"));
    expect(res.message_ids_hex).toEqual([HEX32("de")]);
  });

  it("uploads media and returns the durable message ids from send_media", async () => {
    const res = await client.sendMedia(
      HEX32("aa"),
      HEX32("cc"),
      [{ path: "/tmp/a.png", media_type: "image/png", file_name: "a.png" }],
      "look at this",
    );
    expect(res.message_ids_hex).toEqual([HEX32("11")]);
  });

  it("downloads media and returns the host-local path + metadata", async () => {
    const res = await client.downloadMedia(HEX32("aa"), HEX32("cc"), {
      media_type: "image/png",
      file_name: "a.png",
      ciphertext_sha256: HEX32("cd"),
      plaintext_sha256: HEX32("ab"),
      nonce_hex: "0".repeat(24),
      version: "encrypted-media-v1",
      source_epoch: 7,
      locators: [{ kind: "blossom-v1", value: `https://blossom.example.com/${HEX32("cd")}.bin` }],
    });
    expect(res.type).toBe("media_downloaded");
    expect(res.file_name).toBe("a.png");
    expect(res.size_bytes).toBe(4);
    expect(res.path).toBe("/tmp/marmot-media/abc/a.png");
  });

  it("round-trips group_info (member count + is_direct)", async () => {
    const res = await client.groupInfo(HEX32("aa"), HEX32("cc"));
    expect(res.member_count).toBe(2);
    expect(res.is_direct).toBe(true);
  });

  it("maps an error response to a typed AgentControlError", async () => {
    await expect(client.request({ type: "explode" })).rejects.toMatchObject({
      name: "AgentControlError",
      code: "bad_request",
    });
  });

  it("rejects a mismatched response id", async () => {
    await expect(client.request({ type: "wrong_id" })).rejects.toMatchObject({
      code: "id_mismatch",
    });
  });

  it("rejects a wrong protocol tag", async () => {
    await expect(client.request({ type: "wrong_proto" })).rejects.toMatchObject({
      code: "wrong_protocol",
    });
  });

  it("streams inbound events after the ack until EOF", async () => {
    const events = [];
    for await (const event of client.subscribeInbound({ accountIdHex: HEX32("aa") })) {
      events.push(event);
    }
    expect(events.map((e) => e.type)).toEqual(["inbound_message", "resync_required"]);
    expect(events[0]).toMatchObject({ text: "hello agent", group_id_hex: HEX32("cc") });
  });

  it("surfaces a connection failure as a retryable error", async () => {
    const broken = new MarmotAgentControlClient({
      socketPath: join(dir, "does-not-exist.sock"),
      requestTimeoutMs: 1000,
    });
    await expect(broken.accountList()).rejects.toMatchObject({ retryable: true });
  });
});

describe("preview op timeouts", () => {
  let dir: string;
  let socketPath: string;
  let server: Server;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "oc-marmot-delay-"));
    socketPath = join(dir, "delay.sock");
    // Every response is delayed 400ms: well past the short preview timeout, well
    // under the durable request timeout.
    server = await startServer(socketPath, 400);
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  });

  it("abandons a best-effort preview op at the short preview timeout", async () => {
    const client = new MarmotAgentControlClient({
      socketPath,
      requestTimeoutMs: 3000,
      previewRequestTimeoutMs: 80,
    });
    await expect(client.streamBegin(HEX32("aa"), HEX32("cc"))).rejects.toMatchObject({
      code: "timeout",
    });
  });

  it("still completes a durable send under the full request timeout", async () => {
    const client = new MarmotAgentControlClient({
      socketPath,
      requestTimeoutMs: 3000,
      previewRequestTimeoutMs: 80,
    });
    const res = await client.sendFinal(HEX32("aa"), HEX32("cc"), "done");
    expect(res.message_ids_hex).toEqual([HEX32("ab")]);
  });
});

describe("normalizeHex", () => {
  it("lowercases and strips a 0x prefix", () => {
    expect(normalizeHex("0xABCD")).toBe("abcd");
  });

  it("rejects empty and non-hex input", () => {
    expect(() => normalizeHex("")).toThrow(AgentControlError);
    expect(() => normalizeHex("zz")).toThrow(AgentControlError);
    expect(() => normalizeHex("abc")).toThrow(AgentControlError);
  });
});
