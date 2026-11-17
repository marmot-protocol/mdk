// Packaged-install acceptance for the OpenClaw Marmot plugin release tarball.
//
// Drives the real `openclaw` CLI, in isolated OpenClaw state, through the same
// `openclaw plugins install --force --accept-capabilities <tgz>` step that
// scripts/install-openclaw-marmot.sh runs with `--yes`:
//
//   fresh:   install into empty OpenClaw state.
//   upgrade: install the published 0.11.0 tarball, configure the channel, add
//            wn-agent connector data and a pending Doctor-inspection record,
//            then install this tarball over it.
//
// Run with Node's type stripping (not built, not a Vitest file):
//   node test/packaged-install.ts [--tarball PATH] [--host-version VER | --openclaw-root DIR]
//                                 [--previous-tarball PATH] [--keep]
// Without --tarball the checkout is built and packed the way the release job packs it.
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

const PLUGIN_DIR = resolve(import.meta.dirname, "..");
const REPO_ROOT = resolve(PLUGIN_DIR, "..", "..", "..");
const EXPECTED_TOOLS = ["marmot_group_profile", "marmot_history"];
// The last release whose plugin predates the Doctor contract and tool declarations.
const PREVIOUS_RELEASE = {
  version: "0.11.0",
  url: "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.11.0/openclaw-marmot-plugin-0.11.0.tgz",
  sha256: "833e213119efbdd29b1ad0a4f48494ea14550085aaf00221a71eb2607ad3dca4",
};
// The record OpenClaw's update leaves for a configured channel plugin whose
// legacy setup entry it could not inspect (see inspectPluginMigrationAvailability).
const PENDING_DOCTOR_INSPECTION = {
  pluginId: "marmot",
  requiresDoctorInspection: true,
  reason: "The configured plugin package is missing or has not converged.",
  command: "openclaw update repair",
};
const HEX = (byte: string): string => byte.repeat(32);

interface Options {
  tarball?: string;
  hostVersion?: string;
  openclawRoot?: string;
  previousTarball?: string;
  keep: boolean;
}

interface Diagnostic {
  level?: string;
  pluginId?: string;
  message?: string;
}

interface InspectReport {
  plugin: { id: string; version?: string; status?: string; toolNames?: string[]; error?: string };
  tools?: Array<{ names: string[] }>;
  diagnostics?: Diagnostic[];
  install?: { source?: string; version?: string; installPath?: string };
}

function parseArgs(argv: string[]): Options {
  const options: Options = { keep: false };
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
      case "--previous-tarball": options.previousTarball = resolve(value()); break;
      case "--keep": options.keep = true; break;
      case "-h":
      case "--help":
        console.log("usage: node test/packaged-install.ts [--tarball PATH] [--host-version VER | --openclaw-root DIR] [--previous-tarball PATH] [--keep]");
        process.exit(0);
      default: throw new Error(`unknown option: ${flag}`);
    }
  }
  return options;
}

function run(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}): SpawnSyncReturns<string> {
  return spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: "utf8",
    timeout: options.timeoutMs ?? 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
}

function mustRun(command: string, args: string[], options: Parameters<typeof run>[2] = {}): string {
  const result = run(command, args, options);
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited ${result.status ?? result.signal}\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function check(condition: unknown, message: string, detail?: unknown): asserts condition {
  if (!condition) {
    throw new Error(detail === undefined ? message : `${message}\n${typeof detail === "string" ? detail : JSON.stringify(detail, null, 2)}`);
  }
}

function packFromCheckout(workRoot: string): string {
  mustRun("pnpm", ["build"], { cwd: PLUGIN_DIR });
  const stage = join(workRoot, "pack-stage");
  mkdirSync(stage, { recursive: true });
  const pkg = JSON.parse(readFileSync(join(PLUGIN_DIR, "package.json"), "utf8")) as { files: string[] };
  for (const entry of ["package.json", ".npmrc", ...pkg.files]) {
    if (existsSync(join(PLUGIN_DIR, entry))) cpSync(join(PLUGIN_DIR, entry), join(stage, entry), { recursive: true });
  }
  const workspaceVersion = /^version = "(.+)"$/m.exec(readFileSync(join(REPO_ROOT, "Cargo.toml"), "utf8"))?.[1] ?? "0.0.0";
  const sourceSha = run("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT }).stdout.trim();
  const version = `${workspaceVersion.replace(/-.*$/, "")}-local`;
  writeFileSync(join(stage, "manifest.json"), `${JSON.stringify({
    name: "openclaw-marmot-plugin",
    release_tag: "",
    artifact_version: version,
    source_sha: sourceSha,
    workspace_version: workspaceVersion,
  }, null, 2)}\n`);
  mustRun("npm", ["pkg", "set", `version=${version}`], { cwd: stage });
  const out = join(workRoot, "packed");
  mkdirSync(out);
  mustRun("pnpm", ["pack", "--pack-destination", out], { cwd: stage });
  const packed = readdirSync(out).find((name) => name.endsWith(".tgz"));
  check(packed, "pnpm pack produced no tarball");
  return join(out, packed);
}

function resolveHost(options: Options, workRoot: string): string {
  if (options.openclawRoot) return options.openclawRoot;
  const pinned = (JSON.parse(readFileSync(join(PLUGIN_DIR, "package.json"), "utf8")) as {
    devDependencies: Record<string, string>;
  }).devDependencies.openclaw;
  const version = options.hostVersion ?? pinned;
  const local = join(PLUGIN_DIR, "node_modules", "openclaw", "package.json");
  if (existsSync(local) && (JSON.parse(readFileSync(local, "utf8")) as { version: string }).version === version) {
    return dirname(realpathSync(local));
  }
  const prefix = join(workRoot, `openclaw-${version}`);
  mkdirSync(prefix, { recursive: true });
  writeFileSync(join(prefix, "package.json"), "{\"private\":true}\n");
  mustRun("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error", `openclaw@${version}`], { cwd: prefix, timeoutMs: 900_000 });
  return join(prefix, "node_modules", "openclaw");
}

function previousTarball(options: Options, workRoot: string): string {
  const path = options.previousTarball ?? join(workRoot, "previous", `openclaw-marmot-plugin-${PREVIOUS_RELEASE.version}.tgz`);
  if (!options.previousTarball) {
    mkdirSync(dirname(path), { recursive: true });
    mustRun("curl", ["-fsSL", "--retry", "3", "--connect-timeout", "20", "--max-time", "300", PREVIOUS_RELEASE.url, "-o", path]);
  }
  check(sha256(path) === PREVIOUS_RELEASE.sha256, `previous release tarball checksum mismatch: ${path}`);
  return path;
}

class Host {
  readonly entry: string;
  readonly dist: string;
  readonly version: string;

  constructor(packageRoot: string) {
    const root = realpathSync(packageRoot);
    this.entry = join(root, "openclaw.mjs");
    this.dist = join(root, "dist");
    this.version = (JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string }).version;
  }
}

class OpenClawState {
  readonly root: string;
  readonly home: string;
  readonly stateDir: string;
  readonly host: Host;
  readonly log: string[] = [];

  constructor(host: Host, root: string) {
    this.host = host;
    this.root = root;
    this.home = join(root, "openclaw-home");
    this.stateDir = join(root, "openclaw-state");
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
  }

  env(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env, OPENCLAW_HOME: this.home, OPENCLAW_STATE_DIR: this.stateDir, NO_COLOR: "1", FORCE_COLOR: "0" };
    delete env.OPENCLAW_CONFIG_PATH;
    return env;
  }

  openclaw(args: string[]): SpawnSyncReturns<string> {
    const result = run(process.execPath, [this.host.entry, ...args], { cwd: this.root, env: this.env() });
    this.log.push(`$ openclaw ${args.join(" ")} -> ${result.status ?? result.signal}\n${result.stdout}${result.stderr}`);
    return result;
  }

  install(tarball: string): string {
    const result = this.openclaw(["plugins", "install", "--force", "--accept-capabilities", tarball]);
    const output = `${result.stdout}\n${result.stderr}`;
    check(result.status === 0, `openclaw plugins install failed for ${tarball}`, output);
    check(!/could not be inspected|must declare contracts/.test(output), "install reported a contract failure", output);
    return output;
  }

  inspect(runtime: boolean): InspectReport {
    const result = this.openclaw(["plugins", "inspect", "marmot", "--json", ...(runtime ? ["--runtime"] : [])]);
    check(result.status === 0, "openclaw plugins inspect failed", result.stderr);
    return JSON.parse(result.stdout) as InspectReport;
  }

  // OpenClaw's own deferred-migration store; the named-export chunk avoids pinning a hash.
  deferredMigrations(record?: object): unknown[] {
    const script = `
      import { readdirSync } from "node:fs";
      import { join } from "node:path";
      import { pathToFileURL } from "node:url";
      const [dist, record] = process.argv.slice(1);
      let store;
      for (const file of readdirSync(dist).filter((name) => /^deferred-plugin-migrations-[^.]+\\.mjs$/.test(name))) {
        const mod = await import(pathToFileURL(join(dist, file)).href);
        if (typeof mod.recordDeferredPluginMigrations === "function") { store = mod; break; }
      }
      if (!store) throw new Error("host has no deferred plugin migration store");
      if (record) await store.recordDeferredPluginMigrations({ pending: [JSON.parse(record)], env: process.env });
      process.stdout.write(JSON.stringify(await store.readDeferredPluginMigrationsAsync({ env: process.env })));
    `;
    const result = run(process.execPath, ["--input-type=module", "-e", script, this.host.dist, ...(record ? [JSON.stringify(record)] : [])], {
      cwd: this.root,
      env: this.env(),
    });
    check(result.status === 0, "reading OpenClaw deferred plugin migrations failed", result.stderr);
    const lastLine = result.stdout.trim().split("\n").at(-1) ?? "[]";
    return JSON.parse(lastLine) as unknown[];
  }

  configPath(): string {
    return join(this.stateDir, "openclaw.json");
  }

  readConfig(): Record<string, any> {
    return JSON.parse(readFileSync(this.configPath(), "utf8")) as Record<string, any>;
  }
}

function tarballManifest(tarball: string, workRoot: string): { version: string; doctorStateMigrations: unknown } {
  const dir = mkdtempSync(join(workRoot, "tarball-"));
  mustRun("tar", ["-xzf", tarball, "-C", dir]);
  const pkg = JSON.parse(readFileSync(join(dir, "package", "package.json"), "utf8")) as { version: string };
  const manifest = JSON.parse(readFileSync(join(dir, "package", "openclaw.plugin.json"), "utf8")) as {
    contracts?: { tools?: string[] };
    doctorContract?: { stateMigrations?: unknown };
  };
  check(existsSync(join(dir, "package", "dist", "doctor-contract-api.js")), "tarball is missing dist/doctor-contract-api.js");
  check(isDeepStrictEqual(manifest.contracts?.tools?.toSorted(), EXPECTED_TOOLS), "tarball manifest does not declare the Marmot tools", manifest.contracts);
  check(Array.isArray(manifest.doctorContract?.stateMigrations), "tarball manifest does not declare doctorContract.stateMigrations", manifest.doctorContract);
  return { version: pkg.version, doctorStateMigrations: manifest.doctorContract?.stateMigrations };
}

/** The only accepted plugin diagnostic for an archive install is its provenance classification. */
function assertLoadedRelease(report: InspectReport, version: string): Diagnostic[] {
  check(report.plugin.status === "loaded", `plugin did not load: ${report.plugin.status}`, report.plugin.error ?? report.diagnostics);
  check(report.plugin.version === version, `loaded plugin version ${report.plugin.version} != ${version}`);
  check(report.install?.version === version, `recorded install version ${report.install?.version} != ${version}`);
  check(report.install?.source === "archive", `unexpected install source ${report.install?.source}`);
  check(isDeepStrictEqual(report.plugin.toolNames?.toSorted(), EXPECTED_TOOLS), "plugin tool catalog is incomplete", report.plugin.toolNames);
  check(isDeepStrictEqual(report.tools?.flatMap((tool) => tool.names).toSorted(), EXPECTED_TOOLS), "runtime tool registrations are incomplete", report.tools);
  const diagnostics = (report.diagnostics ?? []).filter((entry) => entry.pluginId === undefined || entry.pluginId === "marmot");
  const provenance = diagnostics.filter((entry) => entry.level === "warn" && /reason=provenance-invalid;.*installSource="archive"/.test(entry.message ?? ""));
  const unexpected = diagnostics.filter((entry) => !provenance.includes(entry));
  check(unexpected.length === 0, "unexpected plugin diagnostics", unexpected);
  return provenance;
}

/** Import the installed entry points through the host SDK the installer linked into the plugin. */
function assertEntryPoints(state: OpenClawState, installPath: string, declared: unknown): void {
  const sdk = realpathSync(join(installPath, "node_modules", "openclaw"));
  const sdkVersion = (JSON.parse(readFileSync(join(sdk, "package.json"), "utf8")) as { version: string }).version;
  check(sdkVersion === state.host.version, `installed plugin links OpenClaw ${sdkVersion}, not the host ${state.host.version}`);
  const script = `
    const main = (await import("./dist/index.js")).default;
    const setup = (await import("./dist/setup-entry.js")).default;
    const doctor = await import("./dist/doctor-contract-api.js");
    process.stdout.write(JSON.stringify({
      main: { id: main?.id, register: typeof main?.register, channel: main?.channelPlugin?.id },
      setup: { channel: setup?.plugin?.id },
      stateMigrations: doctor.stateMigrations,
    }));
  `;
  const result = run(process.execPath, ["--input-type=module", "-e", script], { cwd: installPath, env: state.env() });
  check(result.status === 0, "installed entry points failed to load against the host SDK", result.stderr);
  const loaded = JSON.parse(result.stdout) as { main: Record<string, unknown>; setup: Record<string, unknown>; stateMigrations: unknown };
  check(isDeepStrictEqual(loaded.main, { id: "marmot", register: "function", channel: "marmot" }), "normal entry has the wrong shape", loaded.main);
  check(isDeepStrictEqual(loaded.setup, { channel: "marmot" }), "setup entry has the wrong shape", loaded.setup);
  check(isDeepStrictEqual(loaded.stateMigrations, declared), "Doctor module and manifest declaration differ", loaded);
}

function snapshotTree(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir).toSorted()) {
      const path = join(dir, name);
      const stat = statSync(path);
      if (stat.isDirectory()) {
        out[`${relative(root, path)}/`] = (stat.mode & 0o777).toString(8);
        walk(path);
      } else {
        out[relative(root, path)] = `${(stat.mode & 0o777).toString(8)}:${sha256(path)}`;
      }
    }
  };
  walk(root);
  return out;
}

function seedConnectorData(marmotHome: string): void {
  mkdirSync(join(marmotHome, "dev"), { recursive: true, mode: 0o700 });
  const files: Array<[string, string]> = [
    ["accounts.sqlite", "connector database placeholder"],
    ["dev/control.token", "test-control-token\n"],
    ["dev/profile-onboarding.json", `${JSON.stringify({ version: 1, accounts: { [HEX("aa")]: { status: "named" } } })}\n`],
  ];
  for (const [name, content] of files) {
    writeFileSync(join(marmotHome, name), content, { mode: 0o600 });
    chmodSync(join(marmotHome, name), 0o600);
  }
}

function freshInstall(host: Host, tarball: string, workRoot: string): void {
  const state = new OpenClawState(host, mkdtempSync(join(workRoot, "fresh-")));
  try {
    const expected = tarballManifest(tarball, workRoot);
    state.install(tarball);
    const report = state.inspect(true);
    const provenance = assertLoadedRelease(report, expected.version);
    assertEntryPoints(state, report.install?.installPath ?? "", expected.doctorStateMigrations);
    check(state.deferredMigrations().length === 0, "fresh install left pending plugin migrations");
    console.log(`ok fresh install: ${expected.version} loaded on OpenClaw ${host.version}; tools ${EXPECTED_TOOLS.join(", ")}`);
    console.log(`   archive provenance classification: ${provenance.length > 0 ? "provenance-invalid (expected for local archives)" : "none reported"}`);
  } catch (error) {
    throw new Error(`fresh install failed\n${(error as Error).message}\n\n${state.log.join("\n")}`);
  }
}

function upgradeInstall(host: Host, tarball: string, previous: string, workRoot: string): void {
  const state = new OpenClawState(host, mkdtempSync(join(workRoot, "upgrade-")));
  try {
    const expected = tarballManifest(tarball, workRoot);
    state.install(previous);
    check(state.inspect(false).install?.version === PREVIOUS_RELEASE.version, "previous release was not recorded");

    // Channel identity, sender allowlist, welcomer allowlist, and token file as the installer leaves them.
    const marmotHome = join(state.root, "marmot-home");
    seedConnectorData(marmotHome);
    const config = state.readConfig();
    config.channels = {
      ...(config.channels ?? {}),
      marmot: {
        enabled: true,
        home: marmotHome,
        socketPath: join(marmotHome, "dev", "wn-agent.sock"),
        accountIdHex: HEX("aa"),
        authTokenFile: join(marmotHome, "dev", "control.token"),
        dm: { policy: "allowlist", allowFrom: [HEX("bb")] },
        senderPolicy: { allowedUsers: [HEX("bb"), HEX("cc")] },
        streaming: { mode: "off" },
        profileNameOnboarding: true,
      },
    };
    writeFileSync(state.configPath(), `${JSON.stringify(config, null, 2)}\n`);
    const channelBefore = structuredClone(config.channels.marmot);
    const connectorBefore = snapshotTree(marmotHome);

    const pending = state.deferredMigrations(PENDING_DOCTOR_INSPECTION);
    check(pending.length === 1, "pending Doctor-inspection record was not recorded", pending);

    state.install(tarball);
    check(state.deferredMigrations().length === 0, "upgrade left the pending Doctor inspection");
    const report = state.inspect(true);
    assertLoadedRelease(report, expected.version);
    assertEntryPoints(state, report.install?.installPath ?? "", expected.doctorStateMigrations);
    const after = state.readConfig();
    check(isDeepStrictEqual(after.channels?.marmot, channelBefore), "upgrade changed channels.marmot", { before: channelBefore, after: after.channels?.marmot });
    check(after.plugins?.entries?.marmot?.enabled === true, "upgrade disabled the plugin", after.plugins?.entries?.marmot);
    check(isDeepStrictEqual(snapshotTree(marmotHome), connectorBefore), "upgrade changed wn-agent connector data");
    console.log(`ok upgrade: ${PREVIOUS_RELEASE.version} -> ${expected.version} on OpenClaw ${host.version}; pending inspection cleared; config and connector data preserved`);
  } catch (error) {
    throw new Error(`upgrade from ${PREVIOUS_RELEASE.version} failed\n${(error as Error).message}\n\n${state.log.join("\n")}`);
  }
}

const options = parseArgs(process.argv.slice(2));
const workRoot = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "openclaw-marmot-packaged-"));
let failed = false;
try {
  const tarball = options.tarball ?? packFromCheckout(workRoot);
  const host = new Host(resolveHost(options, workRoot));
  console.log(`packaged install: ${tarball} (sha256 ${sha256(tarball)}) on OpenClaw ${host.version}`);
  freshInstall(host, tarball, workRoot);
  upgradeInstall(host, tarball, previousTarball(options, workRoot), workRoot);
} catch (error) {
  failed = true;
  console.error((error as Error).message);
} finally {
  if (options.keep || failed) {
    console.error(`work root kept: ${workRoot}`);
  } else {
    rmSync(workRoot, { recursive: true, force: true });
  }
}
process.exit(failed ? 1 : 0);
