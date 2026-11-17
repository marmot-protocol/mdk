// Live release acceptance for the packaged OpenClaw Marmot plugin.
//
// Everything except the model is real: a disposable local strfry relay, a real
// `wn-agent`, the `wn` CLI as the White Noise client, and `openclaw gateway run`
// with the release tarball installed through `openclaw plugins install`. A
// scripted OpenAI-compatible endpoint on loopback stands in for the model so the
// agent turn is deterministic; it drives the Marmot tools exactly as a model
// would, through the gateway's own tool catalog and execution path.
//
// The client creates a disposable group with the agent as admin and sends one
// message. The scripted agent turn then:
//   1. checks both Marmot tools are in the catalog the gateway offers the model;
//   2. reads history with marmot_history and finds the client's message;
//   3. fetches that message by exact id;
//   4. submits an over-long group name and expects input validation to reject it;
//   5. renames the disposable group with marmot_group_profile;
//   6. replies, and the client must receive the reply and see the new name.
//
// Run with Node's type stripping:
//   node test/release-acceptance.ts --tarball PATH [--host-version VER | --openclaw-root DIR]
//        [--wn-agent BIN] [--wn BIN (wnd beside it)] [--relay ws://127.0.0.1:PORT] [--keep]
// Requires Docker unless --relay names an already running loopback relay.
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect, createServer as createNetServer } from "node:net";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const PLUGIN_DIR = resolve(import.meta.dirname, "..");
const REPO_ROOT = resolve(PLUGIN_DIR, "..", "..", "..");
const TOOLS = ["marmot_history", "marmot_group_profile"] as const;
const STRFRY_IMAGE = "dockurr/strfry:1.0.4";
const STEP_TIMEOUT_MS = 120_000;

interface Options {
  tarball?: string;
  hostVersion?: string;
  openclawRoot?: string;
  wnAgent: string;
  wn: string;
  relay?: string;
  keep: boolean;
}

function parseArgs(argv: string[]): Options {
  const options: Options = {
    wnAgent: join(REPO_ROOT, "target", "debug", "wn-agent"),
    wn: join(REPO_ROOT, "target", "debug", "wn"),
    keep: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = (): string => {
      const next = argv[index + 1];
      if (next === undefined) throw new Error(`${flag} requires a value`);
      index += 1;
      return next;
    };
    switch (flag) {
      case "--tarball": options.tarball = resolve(value()); break;
      case "--host-version": options.hostVersion = value(); break;
      case "--openclaw-root": options.openclawRoot = resolve(value()); break;
      case "--wn-agent": options.wnAgent = resolve(value()); break;
      case "--wn": options.wn = resolve(value()); break;
      case "--relay": options.relay = value(); break;
      case "--keep": options.keep = true; break;
      default: throw new Error(`unknown option: ${flag}`);
    }
  }
  if (!options.tarball) throw new Error("--tarball is required (see test/packaged-install.ts to build one)");
  return options;
}

function check(condition: unknown, message: string, detail?: unknown): asserts condition {
  if (!condition) {
    throw new Error(detail === undefined ? message : `${message}\n${typeof detail === "string" ? detail : JSON.stringify(detail, null, 2)}`);
  }
}

function runSync(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}): string {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: "utf8",
    timeout: options.timeoutMs ?? STEP_TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited ${result.status ?? result.signal}\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

async function waitFor<T>(label: string, probe: () => Promise<T | undefined> | T | undefined, timeoutMs = STEP_TIMEOUT_MS): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await probe();
      if (value !== undefined) return value;
    } catch (error) {
      lastError = error;
    }
    await new Promise((done) => setTimeout(done, 1_000));
  }
  throw new Error(`timed out waiting for ${label}${lastError ? `: ${(lastError as Error).message}` : ""}`);
}

function freePort(): Promise<number> {
  return new Promise((done, fail) => {
    const server = createNetServer();
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => done(typeof address === "object" && address ? address.port : 0));
    });
  });
}

function tcpReady(port: number): Promise<boolean> {
  return new Promise((done) => {
    const socket = connect({ host: "127.0.0.1", port });
    socket.once("connect", () => { socket.destroy(); done(true); });
    socket.once("error", () => done(false));
  });
}

class Processes {
  readonly children: Array<{ name: string; child: ChildProcess }> = [];
  readonly cleanups: Array<() => void> = [];

  spawn(name: string, command: string, args: string[], env: NodeJS.ProcessEnv, logPath: string): ChildProcess {
    const log = createWriteStream(logPath, { flags: "a" });
    const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout?.pipe(log);
    child.stderr?.pipe(log);
    this.children.push({ name, child });
    return child;
  }

  async stopAll(): Promise<void> {
    for (const { child } of this.children.toReversed()) {
      if (child.exitCode !== null || child.signalCode !== null) continue;
      child.kill("SIGTERM");
      const exited = await Promise.race([
        new Promise<boolean>((done) => child.once("exit", () => done(true))),
        new Promise<boolean>((done) => setTimeout(() => done(false), 10_000)),
      ]);
      if (!exited) child.kill("SIGKILL");
    }
    for (const cleanup of this.cleanups.toReversed()) {
      try { cleanup(); } catch { /* best effort */ }
    }
  }
}

function startRelay(processes: Processes): Promise<string> {
  const containerId = runSync("docker", [
    "run", "-d", "--rm",
    "-p", "127.0.0.1::7777",
    "-v", `${join(REPO_ROOT, "dev", "strfry.conf")}:/etc/strfry.conf:ro`,
    "--tmpfs", "/app/strfry-db:uid=1000,gid=1000",
    STRFRY_IMAGE, "./strfry", "relay",
  ], { timeoutMs: 600_000 }).trim().split("\n").at(-1)!;
  processes.cleanups.push(() => { spawnSync("docker", ["rm", "-f", containerId], { stdio: "ignore" }); });
  const port = Number(runSync("docker", ["port", containerId, "7777"]).trim().split(":").at(-1));
  return waitFor("local relay", async () => (await tcpReady(port)) ? `ws://127.0.0.1:${port}` : undefined, 60_000);
}

// --- Scripted OpenAI-compatible model ----------------------------------------------------

interface ChatMessage {
  role: string;
  content?: unknown;
  tool_calls?: Array<{ id: string; function: { name: string; arguments: string } }>;
  tool_call_id?: string;
}

interface Scenario {
  nonce: string;
  groupIdHex: string;
  clientText: string;
  newGroupName: string;
  replyText: string;
}

interface ModelObservations {
  directoryListsTools: boolean;
  searchedTools: string[];
  promptGroupIdHex?: string;
  toolResults: Array<Record<string, unknown>>;
  replied: boolean;
  errors: string[];
}

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map((part) => (typeof part === "object" && part && "text" in part ? String((part as { text: unknown }).text) : "")).join("");
  }
  return "";
}

/** Parse a tool result; `dispatch_action` wraps the target tool's own result as `{ tool, result }`. */
function toolResult(content: unknown): Record<string, unknown> {
  const text = textOf(content);
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const wrapped = parsed.result as { content?: unknown; details?: unknown } | undefined;
    if (parsed.tool && wrapped && typeof wrapped === "object") {
      const inner = wrapped.details && typeof wrapped.details === "object"
        ? wrapped.details as Record<string, unknown>
        : toolResult(wrapped.content);
      return { ...inner, dispatchedTool: (parsed.tool as { name?: string }).name };
    }
    return parsed;
  } catch {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start !== -1 && end > start) {
      try { return JSON.parse(text.slice(start, end + 1)) as Record<string, unknown>; } catch { /* fall through */ }
    }
    return { unparsed: text };
  }
}

/**
 * Decide the scripted turn's next step from the transcript the gateway sends,
 * the way a model would: OpenClaw's default Tool Search surface lists plugin
 * tools in the system-prompt capability directory, the model finds them with
 * `tool_search`, and calls them through `dispatch_action`.
 */
function nextStep(body: { messages: ChatMessage[]; tools?: Array<{ function?: { name?: string } }> }, scenario: Scenario, seen: ModelObservations):
  | { tool: string; args: Record<string, unknown> }
  | { text: string } {
  const messages = body.messages ?? [];
  const offered = (body.tools ?? []).map((tool) => tool.function?.name ?? "").filter(Boolean);
  const lastUser = messages.findLastIndex((message) => message.role === "user" && textOf(message.content).includes(scenario.nonce));
  // Tool-less requests are host utility calls (titles, summaries), not the agent turn.
  if (lastUser === -1 || offered.length === 0) return { text: "ok" };
  const fail = (error: string): { text: string } => {
    seen.errors.push(error);
    return { text: `acceptance failure: ${error}` };
  };
  const system = messages.filter((message) => message.role === "system" || message.role === "developer").map((message) => textOf(message.content)).join("\n");
  seen.directoryListsTools = TOOLS.every((tool) => system.includes(`- ${tool} (marmot)`) || offered.includes(tool));
  // Conversation info arrives as JSON, possibly re-encoded inside a JSON string.
  const chatId = /\\*"chat_id\\*"\s*:\s*\\*"([0-9a-f]+)/.exec(messages.slice(0, lastUser + 1).map((message) => textOf(message.content)).join("\n"))?.[1];
  seen.promptGroupIdHex = chatId;
  const results = messages.slice(lastUser).filter((message) => message.role === "tool").map((message) => toolResult(message.content));
  seen.toolResults = results;
  const groupIdHex = chatId ?? "";
  const call = (id: string, args: Record<string, unknown>) => ({ tool: "dispatch_action", args: { id, args } });
  switch (results.length) {
    case 0:
      if (!seen.directoryListsTools) return fail("capability directory does not list the Marmot tools");
      if (!chatId) return fail("conversation info carried no chat_id");
      return offered.includes("tool_search") ? { tool: "tool_search", args: { query: "marmot" } } : call("tool_search", {});
    case 1: {
      const text = JSON.stringify(results[0]);
      seen.searchedTools = TOOLS.filter((tool) => text.includes(tool));
      if (seen.searchedTools.length !== TOOLS.length) return fail(`tool_search did not return both Marmot tools: ${text.slice(0, 400)}`);
      return call("marmot_history", { group_id_hex: groupIdHex, limit: 20 });
    }
    case 2: {
      const page = results[1] as { messages?: Array<{ message_id_hex: string; text?: string }> };
      const found = page.messages?.find((message) => message.text === scenario.clientText);
      if (!found) return fail(`history did not contain the client message: ${JSON.stringify(results[1]).slice(0, 400)}`);
      return call("marmot_history", { group_id_hex: groupIdHex, message_id_hex: found.message_id_hex });
    }
    case 3:
      return call("marmot_group_profile", { group_id_hex: groupIdHex, name: "x".repeat(257) });
    case 4:
      return call("marmot_group_profile", { group_id_hex: groupIdHex, name: scenario.newGroupName });
    default:
      seen.replied = true;
      return { text: scenario.replyText };
  }
}

function startModel(scenario: Scenario, seen: ModelObservations, logPath: string): Promise<{ server: Server; port: number }> {
  const log = createWriteStream(logPath, { flags: "a" });
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      if (request.method === "GET" && request.url?.endsWith("/models")) {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ object: "list", data: [{ id: "scripted", object: "model" }] }));
        return;
      }
      if (request.method !== "POST" || !request.url?.endsWith("/chat/completions")) {
        response.writeHead(404).end();
        return;
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Parameters<typeof nextStep>[0] & { stream?: boolean };
      const step = nextStep(body, scenario, seen);
      log.write(`${JSON.stringify({ tools: (body.tools ?? []).map((tool) => tool.function?.name), messages: body.messages.length, step })}\n`);
      const id = `chatcmpl-${randomBytes(6).toString("hex")}`;
      const created = Math.floor(Date.now() / 1000);
      const toolCall = "tool" in step
        ? { index: 0, id: `call_${randomBytes(6).toString("hex")}`, type: "function", function: { name: step.tool, arguments: JSON.stringify(step.args) } }
        : undefined;
      const finish = toolCall ? "tool_calls" : "stop";
      if (!body.stream) {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({
          id, object: "chat.completion", created, model: "scripted",
          choices: [{ index: 0, finish_reason: finish, message: toolCall
            ? { role: "assistant", content: null, tool_calls: [toolCall] }
            : { role: "assistant", content: (step as { text: string }).text } }],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        }));
        return;
      }
      response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      const send = (delta: Record<string, unknown>, finishReason: string | null, usage?: Record<string, number>): void => {
        response.write(`data: ${JSON.stringify({
          id, object: "chat.completion.chunk", created, model: "scripted",
          choices: [{ index: 0, delta, finish_reason: finishReason }],
          ...(usage ? { usage } : {}),
        })}\n\n`);
      };
      send({ role: "assistant", ...(toolCall ? { tool_calls: [toolCall] } : { content: (step as { text: string }).text }) }, null);
      send({}, finish, { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 });
      response.end("data: [DONE]\n\n");
    });
  });
  return new Promise((done) => server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    done({ server, port: typeof address === "object" && address ? address.port : 0 });
  }));
}

// --- Acceptance ------------------------------------------------------------------------

function resolveOpenClawRoot(options: Options, workRoot: string): string {
  if (options.openclawRoot) return realpathSync(options.openclawRoot);
  const pinned = (JSON.parse(readFileSync(join(PLUGIN_DIR, "package.json"), "utf8")) as { devDependencies: Record<string, string> }).devDependencies.openclaw;
  const version = options.hostVersion ?? pinned;
  const local = join(PLUGIN_DIR, "node_modules", "openclaw", "package.json");
  if (existsSync(local) && (JSON.parse(readFileSync(local, "utf8")) as { version: string }).version === version) {
    return realpathSync(join(PLUGIN_DIR, "node_modules", "openclaw"));
  }
  const prefix = join(workRoot, `openclaw-${version}`);
  mkdirSync(prefix, { recursive: true });
  writeFileSync(join(prefix, "package.json"), "{\"private\":true}\n");
  runSync("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error", `openclaw@${version}`], { cwd: prefix, timeoutMs: 900_000 });
  return realpathSync(join(prefix, "node_modules", "openclaw"));
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  for (const binary of [options.wnAgent, options.wn]) check(existsSync(binary), `missing binary ${binary}; build with cargo build -p agent-connector --bin wn-agent -p wn-cli --bin wn`);
  // wn-agent requires an owner-only ancestry and a short Unix socket path.
  const cacheRoot = process.env.XDG_CACHE_HOME?.trim() || join(homedir(), ".cache");
  mkdirSync(cacheRoot, { recursive: true, mode: 0o700 });
  const workRoot = mkdtempSync(join(cacheRoot, "ocmk-"));
  const processes = new Processes();
  let failed = false;
  try {
    const openclawRoot = resolveOpenClawRoot(options, workRoot);
    const hostVersion = (JSON.parse(readFileSync(join(openclawRoot, "package.json"), "utf8")) as { version: string }).version;
    const relay = options.relay ?? await startRelay(processes);
    const rustEnv = { ...process.env, RUST_MIN_STACK: "4194304", RUST_LOG: process.env.RUST_LOG ?? "warn" };

    // White Noise client: a long-running `wnd` daemon, like the app. A one-shot
    // `wn sync` never holds a peer's commit for the settlement window, so it
    // would not apply the agent's rename or decrypt anything sent after it.
    const clientHome = join(workRoot, "client");
    mkdirSync(clientHome, { mode: 0o700 });
    const clientEnv = {
      ...rustEnv,
      WN_SECRET_STORE: "file",
      WN_ALLOW_LOOPBACK_RELAYS: "1",
      PATH: `${resolve(options.wn, "..")}:${process.env.PATH ?? ""}`,
    };
    const wn = (args: string[]): Record<string, any> => {
      const parsed = JSON.parse(runSync(options.wn, ["--home", clientHome, "--json", "--relay", relay, ...args], { env: clientEnv })) as { ok: boolean; result: Record<string, any> };
      check(parsed.ok, `wn ${args.join(" ")} failed`, parsed);
      return parsed.result;
    };
    const clientId = String(wn(["account", "create", "--default-relays", relay, "--bootstrap-relays", relay]).account_id);
    wn(["daemon", "start"]);
    processes.cleanups.push(() => {
      spawnSync(options.wn, ["--home", clientHome, "--json", "daemon", "stop"], { env: clientEnv, stdio: "ignore", timeout: 60_000 });
    });

    // wn-agent, bootstrapped like the installer does, allowing invites from the client.
    const agentHome = join(workRoot, "agent");
    mkdirSync(agentHome, { mode: 0o700 });
    const socketPath = join(agentHome, "a.sock");
    processes.spawn("wn-agent", options.wnAgent, ["--home", agentHome, "--socket", socketPath, "--relay", relay, "--allow-loopback-relays"], rustEnv, join(workRoot, "wn-agent.log"));
    await waitFor("wn-agent socket", () => (existsSync(socketPath) ? true : undefined), 60_000);
    const bootstrap = JSON.parse(runSync(options.wnAgent, [
      "bootstrap", "--json", "--home", agentHome, "--socket", socketPath, "--label", "acceptance",
      "--relay", relay, "--no-quic", "--allow-welcomer", clientId,
    ], { env: rustEnv })) as { account_id_hex: string; key_package_published: boolean };
    check(bootstrap.key_package_published, "wn-agent did not publish a KeyPackage");
    const agentId = bootstrap.account_id_hex;

    // Disposable group with the agent as admin.
    const nonce = randomBytes(4).toString("hex");
    const group = wn(["--account", clientId, "groups", "create", `acceptance-${nonce}`, agentId]);
    const groupIdHex = String(group.group_id ?? (group.group as Record<string, unknown> | undefined)?.group_id);
    check(/^[0-9a-f]+$/.test(groupIdHex), "group create returned no group id", group);
    wn(["--account", clientId, "groups", "promote", groupIdHex, agentId]);
    const scenario: Scenario = {
      nonce,
      groupIdHex,
      clientText: `release acceptance ${nonce}: please check this chat`,
      newGroupName: `acceptance renamed ${nonce}`,
      replyText: `release acceptance reply ${nonce}`,
    };

    // Scripted model and OpenClaw gateway with the packaged plugin.
    const seen: ModelObservations = { directoryListsTools: false, searchedTools: [], toolResults: [], replied: false, errors: [] };
    const model = await startModel(scenario, seen, join(workRoot, "model.log"));
    processes.cleanups.push(() => { model.server.close(); });
    const openclawHome = join(workRoot, "openclaw-home");
    const stateDir = join(workRoot, "openclaw-state");
    mkdirSync(openclawHome, { mode: 0o700 });
    mkdirSync(stateDir, { mode: 0o700 });
    const openclawEnv: NodeJS.ProcessEnv = { ...process.env, OPENCLAW_HOME: openclawHome, OPENCLAW_STATE_DIR: stateDir, NO_COLOR: "1", FORCE_COLOR: "0" };
    delete openclawEnv.OPENCLAW_CONFIG_PATH;
    const openclaw = (args: string[]): string => runSync(process.execPath, [join(openclawRoot, "openclaw.mjs"), ...args], { cwd: workRoot, env: openclawEnv, timeoutMs: 300_000 });
    openclaw(["plugins", "install", "--force", "--accept-capabilities", options.tarball!]);
    const configPath = join(stateDir, "openclaw.json");
    const config = JSON.parse(readFileSync(configPath, "utf8")) as Record<string, any>;
    const modelRef = "acceptance/scripted";
    config.models = {
      mode: "merge",
      providers: {
        acceptance: {
          baseUrl: `http://127.0.0.1:${model.port}/v1`,
          apiKey: "acceptance",
          api: "openai-completions",
          models: [{ id: "scripted", name: "Scripted acceptance model", reasoning: false, input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 128000, maxTokens: 4096 }],
        },
      },
    };
    config.agents = { ...(config.agents ?? {}), defaults: { ...(config.agents?.defaults ?? {}), model: { primary: modelRef }, utilityModel: modelRef, workspace: join(workRoot, "workspace") } };
    config.channels = {
      ...(config.channels ?? {}),
      marmot: {
        enabled: true,
        home: agentHome,
        socketPath,
        accountIdHex: agentId,
        senderPolicy: { allowedUsers: [clientId] },
        dm: { allowFrom: [clientId] },
        streaming: { mode: "off" },
        profileNameOnboarding: false,
      },
    };
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
    const gatewayLog = join(workRoot, "gateway.log");
    const gatewayPort = await freePort();
    processes.spawn("openclaw-gateway", process.execPath, [
      join(openclawRoot, "openclaw.mjs"), "gateway", "run", "--allow-unconfigured", "--auth", "none", "--bind", "loopback", "--port", String(gatewayPort),
    ], openclawEnv, gatewayLog);
    await waitFor("Marmot inbound subscription in the gateway", () => (
      existsSync(gatewayLog) && /inbound subscription established/.test(readFileSync(gatewayLog, "utf8")) ? true : undefined
    ), 180_000);

    // White Noise message -> agent turn -> reply.
    wn(["--account", clientId, "message", "send", "--group", groupIdHex, scenario.clientText]);
    const reply = await waitFor("agent reply at the client", () => {
      if (seen.errors.length > 0) return {};
      const listed = wn(["--account", clientId, "message", "list", "--group", groupIdHex]) as { messages?: Array<Record<string, any>> };
      return listed.messages?.find((message) => message.plaintext === scenario.replyText);
    }, 180_000);
    check(seen.errors.length === 0, "scripted agent turn failed", seen.errors);
    check(seen.replied, "the agent turn never reached the reply step");

    check(seen.promptGroupIdHex === groupIdHex, "conversation chat_id is not the Marmot group id", { prompt: seen.promptGroupIdHex, group: groupIdHex });
    const [, history, exact, invalid, rename] = seen.toolResults;
    check(history?.dispatchedTool === "marmot_history" && history.ok === true && Array.isArray(history.messages), "marmot_history page failed", history);
    check(exact?.dispatchedTool === "marmot_history" && exact.ok === true && JSON.stringify(exact).includes(scenario.clientText), "marmot_history exact lookup failed", exact);
    check(invalid?.dispatchedTool === "marmot_group_profile" && invalid.ok === false && invalid.error === "invalid_group_profile_input", "marmot_group_profile accepted invalid input", invalid);
    check(rename?.dispatchedTool === "marmot_group_profile" && rename.ok === true, "marmot_group_profile rename failed", rename);
    const renamed = await waitFor("renamed group at the client", () => {
      const shown = wn(["--account", clientId, "groups", "show", groupIdHex]);
      return JSON.stringify(shown).includes(scenario.newGroupName) ? shown : undefined;
    });

    console.log(`ok release acceptance on OpenClaw ${hostVersion} with ${options.tarball}`);
    console.log(`   capability directory lists ${TOOLS.join(", ")}; tool_search returned ${seen.searchedTools.join(", ")}`);
    console.log("   history page, exact-message lookup, profile validation, and disposable-group rename passed");
    console.log(`   reply reached the White Noise client (${String(reply.message_id ?? reply.id ?? "").slice(0, 8)}…); group renamed: ${Boolean(renamed)}`);
  } catch (error) {
    failed = true;
    console.error((error as Error).message);
  } finally {
    await processes.stopAll();
    if (options.keep || failed) {
      console.error(`work root kept (logs: wn-agent.log, gateway.log, model.log): ${workRoot}`);
    } else {
      rmSync(workRoot, { recursive: true, force: true });
    }
  }
  process.exit(failed ? 1 : 0);
}

await main();
