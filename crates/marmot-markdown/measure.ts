#!/usr/bin/env bun
/**
 * Run with Bun on Linux + a working systemd user manager:
 * bun crates/marmot-markdown/measure.ts --baseline /path/to/original/crate \
 *   --candidate crates/marmot-markdown --output /tmp/markdown-measurements
 *
 * Defaults: seven alternating build pairs, nine alternating runtime pairs per
 * case, baseline-calibrated >=150ms samples. No samples are discarded.
 * --full-graph also times release compilation into fresh dependency targets.
 * --help describes the methodology. All Cargo descendants live in one limited
 * cgroup; failure to establish that cgroup is fatal, never an unlimited fallback.
 */
import { availableParallelism, cpus } from "node:os";
import { createHash } from "node:crypto";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const MAX_RUNTIME_RATIO = 0.95;
const HELP = `Usage: bun measure.ts --baseline CRATE --candidate CRATE --output NEW_DIRECTORY
  --build-samples N     Alternating pairs per build mode (default 7, minimum 5)
  --runtime-samples N   Alternating pairs per case (default 9, minimum 7)
  --sample-ms N         Baseline calibration floor (default 150, minimum 100)
  --full-graph          Additionally measure fresh-target release graph builds

The same Rust example, golden inputs, dependency versions, lockfile, toolchain,
and profile settings are used for both implementations. Only crate src/,
build.rs, and odin/ differ. Inputs are staged; neither input tree is modified.

Release clean-library samples use cargo clean -p marmot-markdown --release,
then cargo build --release --lib, with dependency artifacts retained. Native
archives and build-script outputs must be absent after cleaning: Odin compile
and static archive incorporation are included, not a cached external artifact.
This is library compilation, not final application executable linking. Dev
clean builds, dev source-edit incremental builds, and release/dev no-op builds
are reported separately. Incremental edits append comments to staged lib.rs;
these measure a Rust source edit, not an Odin edit. Optional full-graph results
use a fresh target each time (download/registry caches remain warm).

Runtime samples invoke public Rust parse, including AST conversion/allocation
and destruction. Corpus setup, process startup and reporting are excluded from
the Rust timer. Both binaries run on the first CPU permitted by the process
affinity mask; metadata records that CPU. Builds retain the full limited CPU
quota. Baseline alone determines fixed per-case iteration counts used
by both binaries. Repeated pair order alternates AB/BA. Each sample is emitted;
every per-case median ratio must meet the runtime gate. Geometric means,
all per-case ratios and regressions are reported. Aggregate timings are
diagnostic only; they cannot hide a failing input class.

Exit 0 requires EVERY runtime case candidate/baseline <=${MAX_RUNTIME_RATIO.toFixed(2)} AND median clean
release library compilation candidate/baseline <=0.50; otherwise exit 1.
Setup/build/resource failures exit 2, without claiming a measurement result.
Outputs: events.jsonl (raw records), summary.json, metadata.json, staged inputs,
and command logs. Output directory must not already exist.

Linux systemd cgroup CPU quota is 80% of available logical CPUs, Cargo jobs are
bounded accordingly, memory is capped at min(16GiB, MemAvailable-8GiB-512MiB),
swap is disabled, and an outer 100ms watchdog kills the entire unit if global
MemAvailable falls below 8GiB. External processes can still cause transient
pressure between samples; a reserve breach invalidates the run.
`;

const argv = Bun.argv.slice(2);
if (argv.includes("--help")) {
  console.log(HELP);
  process.exit(0);
}
function option(name: string, fallback?: string): string {
  const at = argv.indexOf(name);
  if (at < 0) {
    if (fallback !== undefined) {
      return fallback;
    }
    throw new Error(`Missing ${name}; use --help`);
  }
  const value = argv[at + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`Missing value for ${name}`);
  }
  return value;
}
function integerOption(
  name: string,
  fallback: number,
  minimum: number,
): number {
  const value = Number(option(name, String(fallback)));
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be >=${minimum}`);
  }
  return value;
}
const baseline = resolve(option("--baseline"));
const candidate = resolve(option("--candidate"));
const output = resolve(option("--output"));
const buildSamples = integerOption("--build-samples", 7, 5);
const runtimeSamples = integerOption("--runtime-samples", 9, 7);
const sampleMs = integerOption("--sample-ms", 150, 100);
const fullGraph = argv.includes("--full-graph");
const inside = argv.includes("--inside-limit");
const reserve = 8 * 1024 ** 3;
async function availableMemory(): Promise<number> {
  const text = await readFile("/proc/meminfo", "utf8");
  const match = text.match(/^MemAvailable:\s+(\d+) kB$/m);
  if (!match) {
    throw new Error("Cannot read Linux MemAvailable");
  }
  return Number(match[1]) * 1024;
}

type CorpusCase = { case: string; bytes: number; fnv1a64: string };
function corpusRecord(value: unknown): CorpusCase {
  if (
    !value ||
    typeof value !== "object" ||
    !("case" in value) ||
    typeof value.case !== "string" ||
    !("bytes" in value) ||
    typeof value.bytes !== "number" ||
    !Number.isSafeInteger(value.bytes) ||
    value.bytes <= 0 ||
    !("fnv1a64" in value) ||
    typeof value.fnv1a64 !== "string" ||
    !/^[0-9a-f]{16}$/.test(value.fnv1a64)
  ) {
    throw new Error("Invalid corpus record");
  }
  return { case: value.case, bytes: value.bytes, fnv1a64: value.fnv1a64 };
}
function parseCorpus(text: string): CorpusCase[] {
  const records = text
    .trim()
    .split("\n")
    .map((line) => corpusRecord(JSON.parse(line)));
  if (
    records.length !== 13 ||
    new Set(records.map((record) => record.case)).size !== records.length
  ) {
    throw new Error("Incomplete or duplicate corpus");
  }
  return records;
}
function parseSample(text: string) {
  const value: unknown = JSON.parse(text);
  const identity = corpusRecord(value);
  if (
    !value ||
    typeof value !== "object" ||
    !("iterations" in value) ||
    typeof value.iterations !== "number" ||
    !Number.isSafeInteger(value.iterations) ||
    value.iterations <= 0 ||
    !("elapsed_ns" in value) ||
    typeof value.elapsed_ns !== "number" ||
    !Number.isFinite(value.elapsed_ns) ||
    value.elapsed_ns <= 0 ||
    !("ns_per_parse" in value) ||
    typeof value.ns_per_parse !== "number" ||
    !Number.isFinite(value.ns_per_parse) ||
    value.ns_per_parse <= 0
  ) {
    throw new Error("Invalid runtime sample");
  }
  return {
    ...identity,
    iterations: value.iterations,
    elapsed_ns: value.elapsed_ns,
    ns_per_parse: value.ns_per_parse,
  };
}

if (!inside) {
  const before = await availableMemory();
  if (before <= reserve + 1024 ** 3) {
    throw new Error("Need 8GiB reserve plus at least 1GiB free headroom");
  }
  const memoryLimit = Math.floor(
    Math.min(16 * 1024 ** 3, before - reserve - 512 * 1024 ** 2),
  );
  const logicalCpus = Math.min(availableParallelism(), cpus().length);
  const cpuQuota = logicalCpus * 80;
  const jobs = Math.max(1, Math.floor(logicalCpus * 0.8));
  const unit = `marmot-markdown-measure-${process.pid}-${Date.now()}`;
  const resources = {
    logicalCpus,
    cpuQuotaPercent: cpuQuota,
    jobs,
    memoryLimit,
    reserve,
    watchdogMs: 100,
  };
  try {
    // Reserve ownership before the launcher inspects any result files.
    await mkdir(output);
  } catch (error) {
    console.error(error);
    process.exit(2);
  }
  const child = Bun.spawn(
    [
      "systemd-run",
      "--user",
      "--pipe",
      "--wait",
      "--collect",
      `--unit=${unit}`,
      `--property=CPUQuota=${cpuQuota}%`,
      `--property=MemoryMax=${memoryLimit}`,
      "--property=MemorySwapMax=0",
      "--property=KillMode=control-group",
      `--working-directory=${process.cwd()}`,
      `--setenv=MARKDOWN_MEASURE_RESOURCES=${JSON.stringify(resources)}`,
      ...[
        "PATH",
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "ODIN",
        "LD_LIBRARY_PATH",
      ]
        .filter((key) => process.env[key] !== undefined)
        .map((key) => `--setenv=${key}=${process.env[key]}`),
      process.execPath,
      resolve(Bun.main),
      ...argv,
      "--inside-limit",
    ],
    {
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
      env: process.env,
    },
  );
  let breached = false;
  let stopping = false;
  const stop = async () => {
    if (stopping) {
      return;
    }
    stopping = true;
    const killer = Bun.spawn(
      [
        "systemctl",
        "--user",
        "kill",
        "--kill-whom=all",
        "--signal=KILL",
        `${unit}.service`,
      ],
      {
        stdout: "inherit",
        stderr: "inherit",
      },
    );
    await killer.exited;
  };
  const timer = setInterval(async () => {
    try {
      if ((await availableMemory()) < reserve) {
        breached = true;
        console.error(
          "Invalidating measurement: preserving 8GiB available RAM",
        );
        await stop();
      }
    } catch (error) {
      breached = true;
      console.error(error);
      await stop();
    }
  }, 100);
  for (const signal of ["SIGINT", "SIGTERM"] as const)
    process.on(signal, () => {
      breached = true;
      void stop();
    });
  const code = await child.exited;
  clearInterval(timer);
  if (breached) {
    // A completed-looking summary must not survive a resource-invalid run.
    if (await Bun.file(join(output, "summary.json")).exists()) {
      await writeFile(
        join(output, "INVALID_RESOURCE_RUN"),
        "8GiB reserve breached or execution interrupted. Discard all timing results.\n",
      );
    }
  }
  let exitCode = breached ? 2 : code;
  if (
    exitCode !== 0 &&
    !(await Bun.file(join(output, "summary.json")).exists())
  ) {
    exitCode = 2;
  }
  process.exit(exitCode);
}

if (!process.env.MARKDOWN_MEASURE_RESOURCES) {
  throw new Error("Internal mode requires the resource launcher");
}
// Refuse bypassing the launcher: this process must really be in its named cgroup.
const cgroup = await readFile("/proc/self/cgroup", "utf8");
if (!cgroup.includes("marmot-markdown-measure-")) {
  throw new Error("Resource cgroup not established");
}
const resources: unknown = JSON.parse(process.env.MARKDOWN_MEASURE_RESOURCES);
if (
  !resources ||
  typeof resources !== "object" ||
  !("jobs" in resources) ||
  typeof resources.jobs !== "number" ||
  !Number.isSafeInteger(resources.jobs) ||
  resources.jobs < 1
) {
  throw new Error("Invalid resource launcher configuration");
}
const affinity = (await readFile("/proc/self/status", "utf8")).match(
  /^Cpus_allowed_list:\s*(\d+)/m,
);
if (!affinity) {
  throw new Error("Cannot determine permitted runtime CPU");
}
const runtimeCpu = Number(affinity[1]);
const affinityArgs = ["taskset", "-c", String(runtimeCpu)];
await mkdir(join(output, "logs"));
const eventsPath = join(output, "events.jsonl");
await writeFile(eventsPath, "");
async function emit(record: object) {
  const line = JSON.stringify(record);
  await appendFile(eventsPath, line + "\n");
  console.log(line);
}
const env: Record<string, string> = {};
for (const [key, value] of Object.entries(process.env)) {
  if (
    value !== undefined &&
    !key.startsWith("CARGO_PROFILE_") &&
    ![
      "CARGO_TARGET_DIR",
      "CARGO_BUILD_TARGET",
      "CARGO_ENCODED_RUSTFLAGS",
      "RUSTFLAGS",
      "RUSTC_WRAPPER",
      "RUSTC_WORKSPACE_WRAPPER",
      "CARGO_INCREMENTAL",
      "RUSTUP_TOOLCHAIN",
    ].includes(key)
  ) {
    env[key] = value;
  }
}
Object.assign(env, {
  CARGO_BUILD_JOBS: String(resources.jobs),
  RUSTFLAGS: "",
  CARGO_ENCODED_RUSTFLAGS: "",
  RUSTC_WRAPPER: "",
  RUSTC_WORKSPACE_WRAPPER: "",
  CARGO_TERM_COLOR: "never",
});
let commandNumber = 0;
let cargoExecutable = "cargo";
let rustcExecutable = "rustc";
async function command(
  args: string[],
  cwd: string,
  target?: string,
): Promise<{ ms: number; stdout: string }> {
  const id = String(++commandNumber).padStart(4, "0");
  args = [
    args[0] === "cargo"
      ? cargoExecutable
      : args[0] === "rustc"
        ? rustcExecutable
        : args[0],
    ...args.slice(1),
  ];
  const started = performance.now();
  const child = Bun.spawn(args, {
    cwd,
    env: target ? { ...env, CARGO_TARGET_DIR: target } : env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  const ms = performance.now() - started;
  await writeFile(
    join(output, "logs", `${id}.json`),
    JSON.stringify({ args, cwd, target, code, ms }, null, 2),
  );
  await writeFile(join(output, "logs", `${id}.stdout`), stdout);
  await writeFile(join(output, "logs", `${id}.stderr`), stderr);
  if (code !== 0) {
    throw new Error(
      `Command failed (${code}): ${args.join(" ")}; see logs/${id}.stderr`,
    );
  }
  return { ms, stdout };
}
const manifest = `[package]
name = "marmot-markdown"
version = "0.15.0-dev"
edition = "2024"
rust-version = "1.91.0"

[workspace]

[dependencies]
serde = { version = "=1.0.228", features = ["derive"] }

[dev-dependencies]
serde_json = "=1.0.149"

[profile.dev]
opt-level = 0
debug = 2
incremental = true

[profile.dev.package."*"]
debug = false

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
incremental = false
strip = "none"

[lints.rust]
unsafe_code = "deny"
`;
type Side = "baseline" | "candidate";
const sides: Side[] = ["baseline", "candidate"];
const splitAst: Record<Side, boolean> = { baseline: false, candidate: false };
const staged = Object.fromEntries(
  sides.map((side) => [side, join(output, side)]),
) as Record<Side, string>;
const targets = Object.fromEntries(
  sides.map((side) => [side, join(output, `target-${side}`)]),
) as Record<Side, string>;
const harness = join(dirname(resolve(Bun.main)), "examples", "measure.rs");
const golden = join(candidate, "tests", "golden");
const toolchain = join(
  dirname(resolve(Bun.main)),
  "..",
  "..",
  "rust-toolchain.toml",
);
async function optionalCopy(source: string, destination: string) {
  try {
    await stat(source);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return;
    }
    throw error;
  }
  await cp(source, destination, { recursive: true });
}
async function fingerprintTree(root: string): Promise<string> {
  const hash = createHash("sha256");
  async function visit(relative: string) {
    for (const entry of (
      await readdir(join(root, relative), { withFileTypes: true })
    ).sort((a, b) => a.name.localeCompare(b.name, "en"))) {
      const path = join(relative, entry.name);
      if (entry.isDirectory()) {
        await visit(path);
      } else if (entry.isFile()) {
        hash.update(path);
        hash.update("\0");
        hash.update(await readFile(join(root, path)));
        hash.update("\0");
      } else {
        throw new Error(`Unexpected non-regular staged input: ${path}`);
      }
    }
  }
  await visit("");
  return hash.digest("hex");
}
function pair(round: number): Side[] {
  return round % 2 === 0 ? sides : [...sides].reverse();
}
function median(values: number[]): number {
  if (
    !values.length ||
    values.some((value) => !Number.isFinite(value) || value <= 0)
  ) {
    throw new Error("Invalid measurement sample");
  }
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}
const builds: Record<string, Record<Side, number[]>> = {};
async function buildSample(
  mode: string,
  side: Side,
  round: number,
  profile: "release" | "dev",
  target = targets[side],
) {
  const args = [
    "cargo",
    "build",
    "--locked",
    "--offline",
    "--lib",
    ...(profile === "release" ? ["--release"] : []),
  ];
  const result = await command(args, staged[side], target);
  (builds[mode] ??= { baseline: [], candidate: [] })[side].push(result.ms);
  await emit({
    kind: "build_sample",
    mode,
    side,
    round,
    elapsed_ms: result.ms,
  });
}
async function cleanCrate(side: Side, profile: "release" | "dev") {
  await command(
    [
      "cargo",
      "clean",
      "--locked",
      "--offline",
      "-p",
      "marmot-markdown",
      ...(splitAst[side] ? ["-p", "marmot-markdown-ast"] : []),
      ...(profile === "release" ? ["--release"] : []),
    ],
    staged[side],
    targets[side],
  );
  const buildDir = join(
    targets[side],
    profile === "release" ? "release" : "debug",
    "build",
  );
  for (const name of await readdir(buildDir)) {
    if (!name.startsWith("marmot-markdown-")) {
      continue;
    }
    // cargo clean -p must delete this package's OUT_DIR, including Odin's archive.
    const out = join(buildDir, name, "out");
    let entries: string[];
    try {
      entries = await readdir(out);
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        error.code === "ENOENT"
      ) {
        continue;
      }
      throw error;
    }
    if (entries.length) {
      throw new Error(`Native build outputs survived crate clean: ${out}`);
    }
  }
}

try {
  for (const side of sides) {
    const source = side === "baseline" ? baseline : candidate;
    await mkdir(staged[side]);
    await cp(join(source, "src"), join(staged[side], "src"), {
      recursive: true,
    });
    await optionalCopy(
      join(source, "build.rs"),
      join(staged[side], "build.rs"),
    );
    await optionalCopy(join(source, "odin"), join(staged[side], "odin"));
    await mkdir(join(staged[side], "examples"));
    await mkdir(join(staged[side], "tests"));
    await cp(harness, join(staged[side], "examples", "measure.rs"));
    await cp(golden, join(staged[side], "tests", "golden"), {
      recursive: true,
    });
    await cp(toolchain, join(staged[side], "rust-toolchain.toml"));
    splitAst[side] = (
      await readFile(join(source, "Cargo.toml"), "utf8")
    ).includes("marmot-markdown-ast");
    let sideManifest = manifest;
    if (splitAst[side]) {
      const ast = join(staged[side], "ast");
      await mkdir(ast);
      await cp(
        join(dirname(source), "marmot-markdown-ast", "src"),
        join(ast, "src"),
        { recursive: true },
      );
      await writeFile(
        join(ast, "Cargo.toml"),
        `[package]\nname = "marmot-markdown-ast"\nversion = "0.15.0-dev"\nedition = "2024"\n[dependencies]\nserde = { version = "=1.0.228", features = ["derive"] }\n`,
      );
      sideManifest = manifest
        .replace("[workspace]", '[workspace]\nmembers = ["ast"]')
        .replace(
          'serde = { version = "=1.0.228", features = ["derive"] }',
          'marmot-markdown-ast = { path = "ast" }',
        );
    }
    await writeFile(join(staged[side], "Cargo.toml"), sideManifest);
  }
  const channel = (await readFile(toolchain, "utf8")).match(
    /^channel\s*=\s*"([^"]+)"/m,
  )?.[1];
  if (!channel) {
    throw new Error("Repository rust-toolchain.toml must declare a channel");
  }
  cargoExecutable = (
    await command(
      ["rustup", "which", "--toolchain", channel, "cargo"],
      staged.baseline,
    )
  ).stdout.trim();
  rustcExecutable = (
    await command(
      ["rustup", "which", "--toolchain", channel, "rustc"],
      staged.baseline,
    )
  ).stdout.trim();
  env.RUSTC = rustcExecutable;
  env.RUSTUP_TOOLCHAIN = channel;
  await command(
    ["cargo", "generate-lockfile"],
    staged.baseline,
    targets.baseline,
  );
  await cp(
    join(staged.baseline, "Cargo.lock"),
    join(staged.candidate, "Cargo.lock"),
  );
  // Fetch dev dependencies too, so example compilation can remain offline even
  // when the caller has never previously downloaded serde_json.
  await command(
    ["cargo", "fetch", "--locked"],
    staged.baseline,
    targets.baseline,
  );
  if (splitAst.candidate) {
    await command(
      ["cargo", "generate-lockfile", "--offline"],
      staged.candidate,
      targets.candidate,
    );
  }
  const dependencyGraphs = await Promise.all(
    sides.map(async (side) => {
      const lock = Bun.TOML.parse(
        await readFile(join(staged[side], "Cargo.lock"), "utf8"),
      ) as {
        package: {
          name: string;
          version: string;
          source?: string;
          checksum?: string;
          dependencies?: string[];
        }[];
      };
      return JSON.stringify(
        lock.package
          .filter(
            (item) =>
              item.name !== "marmot-markdown" &&
              item.name !== "marmot-markdown-ast",
          )
          .map((item) => [
            item.name,
            item.version,
            item.source ?? "",
            item.checksum ?? "",
            item.dependencies?.toSorted() ?? [],
          ])
          .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
      );
    }),
  );
  if (dependencyGraphs[0] !== dependencyGraphs[1]) {
    throw new Error(
      "Baseline and candidate third-party dependency graphs differ",
    );
  }
  const metadata = {
    schema: 1,
    baseline,
    candidate,
    created_utc: new Date().toISOString(),
    resources,
    cgroup,
    runtime_cpu: runtimeCpu,
    buildSamples,
    runtimeSamples,
    sampleMs,
    fullGraph,
    manifest,
    splitAst,
    toolchain_channel: channel,
    source_sha256: {
      baseline: await fingerprintTree(staged.baseline),
      candidate: await fingerprintTree(staged.candidate),
    },
    harness_sha256: createHash("sha256")
      .update(await readFile(harness))
      .digest("hex"),
    rustc: (
      await command(["rustc", "--version", "--verbose"], staged.baseline)
    ).stdout.trim(),
    cargo: (
      await command(["cargo", "--version"], staged.baseline)
    ).stdout.trim(),
    methodology: HELP,
  };
  await writeFile(
    join(output, "metadata.json"),
    JSON.stringify(metadata, null, 2),
  );
  // Warm dependency artifacts independently for each implementation and profile.
  // These preparation builds are recorded in command logs, never mixed into samples.
  for (const profile of ["release", "dev"] as const) {
    for (const side of sides)
      await command(
        [
          "cargo",
          "build",
          "--locked",
          "--lib",
          ...(profile === "release" ? ["--release"] : []),
        ],
        staged[side],
        targets[side],
      );
    for (let round = 0; round < buildSamples; round++) {
      for (const side of pair(round)) {
        await cleanCrate(side, profile);
        await buildSample(`${profile}_clean_crate`, side, round, profile);
      }
    }
    for (let round = 0; round < buildSamples; round++) {
      for (const side of pair(round))
        await buildSample(`${profile}_noop`, side, round, profile);
    }
  }
  const originals = Object.fromEntries(
    await Promise.all(
      sides.map(async (side) => [
        side,
        await readFile(join(staged[side], "src", "lib.rs"), "utf8"),
      ]),
    ),
  ) as Record<Side, string>;
  for (let round = 0; round < buildSamples; round++) {
    for (const side of pair(round)) {
      await writeFile(
        join(staged[side], "src", "lib.rs"),
        `${originals[side]}\n// measurement-only source edit ${round}\n`,
      );
      await buildSample("dev_source_edit_incremental", side, round, "dev");
    }
  }
  for (const side of sides)
    await writeFile(join(staged[side], "src", "lib.rs"), originals[side]);
  if (fullGraph) {
    for (let round = 0; round < buildSamples; round++) {
      for (const side of pair(round))
        await buildSample(
          "release_full_graph_warm_downloads",
          side,
          round,
          "release",
          join(output, `full-graph-${round}-${side}`),
        );
    }
  }
  for (const side of sides)
    await command(
      [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--offline",
        "--example",
        "measure",
      ],
      staged[side],
      targets[side],
    );
  const binary = (side: Side) =>
    join(targets[side], "release", "examples", "measure");
  const corpus = parseCorpus(
    (
      await command(
        [...affinityArgs, binary("baseline"), "--list"],
        staged.baseline,
      )
    ).stdout,
  );
  const candidateCorpus = parseCorpus(
    (
      await command(
        [...affinityArgs, binary("candidate"), "--list"],
        staged.candidate,
      )
    ).stdout,
  );
  if (JSON.stringify(corpus) !== JSON.stringify(candidateCorpus)) {
    throw new Error("Corpus IDs/content differ");
  }
  await writeFile(join(output, "corpus.json"), JSON.stringify(corpus, null, 2));
  const perCase = [];
  for (const entry of corpus) {
    const calibration = parseSample(
      (
        await command(
          [
            ...affinityArgs,
            binary("baseline"),
            "--case",
            entry.case,
            "--calibrate-ms",
            String(sampleMs),
          ],
          staged.baseline,
        )
      ).stdout,
    );
    if (
      calibration.case !== entry.case ||
      calibration.bytes !== entry.bytes ||
      calibration.fnv1a64 !== entry.fnv1a64
    ) {
      throw new Error("Calibration identity differs");
    }
    await emit({ kind: "calibration", ...calibration });
    const samples: Record<Side, number[]> = { baseline: [], candidate: [] };
    for (let round = 0; round < runtimeSamples; round++) {
      for (const side of pair(round)) {
        const sample = parseSample(
          (
            await command(
              [
                ...affinityArgs,
                binary(side),
                "--case",
                entry.case,
                "--iterations",
                String(calibration.iterations),
              ],
              staged[side],
            )
          ).stdout,
        );
        if (
          sample.case !== entry.case ||
          sample.fnv1a64 !== entry.fnv1a64 ||
          sample.bytes !== entry.bytes ||
          sample.iterations !== calibration.iterations
        ) {
          throw new Error("Runtime sample identity differs");
        }
        samples[side].push(sample.ns_per_parse);
        await emit({ kind: "runtime_sample", side, round, ...sample });
      }
    }
    const baselineNs = median(samples.baseline);
    const candidateNs = median(samples.candidate);
    const result = {
      ...entry,
      iterations: calibration.iterations,
      baseline_ns: baselineNs,
      candidate_ns: candidateNs,
      ratio: candidateNs / baselineNs,
      regression: candidateNs > baselineNs,
      samples_ns: samples,
    };
    perCase.push(result);
    await emit({ kind: "runtime_case_summary", ...result });
  }
  const buildSummary = Object.fromEntries(
    Object.entries(builds).map(([mode, values]) => {
      const baselineMs = median(values.baseline);
      const candidateMs = median(values.candidate);
      return [
        mode,
        {
          baseline_ms: baselineMs,
          candidate_ms: candidateMs,
          ratio: candidateMs / baselineMs,
          samples_ms: values,
        },
      ];
    }),
  );
  const baselineNs = perCase.reduce((sum, entry) => sum + entry.baseline_ns, 0);
  const candidateNs = perCase.reduce(
    (sum, entry) => sum + entry.candidate_ns,
    0,
  );
  const runtimeRatio = Math.exp(
    perCase.reduce((sum, entry) => sum + Math.log(entry.ratio), 0) /
      perCase.length,
  );
  const worstCaseRatio = Math.max(...perCase.map((entry) => entry.ratio));
  const failingCases = perCase
    .filter((entry) => entry.ratio > MAX_RUNTIME_RATIO)
    .map((entry) => ({ case: entry.case, ratio: entry.ratio }));
  const releaseRatio = buildSummary.release_clean_crate.ratio;
  const summary = {
    schema: 1,
    runtime: {
      aggregation: "equally weighted geometric mean of per-case median ratios",
      ratio: runtimeRatio,
      summed_median_diagnostic: {
        baseline_ns: baselineNs,
        candidate_ns: candidateNs,
        ratio: candidateNs / baselineNs,
      },
      regressions: perCase
        .filter((entry) => entry.regression)
        .map((entry) => ({ case: entry.case, ratio: entry.ratio })),
      cases: perCase,
    },
    builds: buildSummary,
    gates: {
      runtime: {
        maximum_ratio: MAX_RUNTIME_RATIO,
        ratio: worstCaseRatio,
        failing_cases: failingCases,
        passed: failingCases.length === 0,
      },
      release_clean_library: {
        maximum_ratio: 0.5,
        ratio: releaseRatio,
        passed: releaseRatio <= 0.5,
      },
    },
    passed: failingCases.length === 0 && releaseRatio <= 0.5,
  };
  await writeFile(
    join(output, "summary.json"),
    JSON.stringify(summary, null, 2),
  );
  await emit({ kind: "summary", ...summary });
  process.exitCode = summary.passed ? 0 : 1;
} catch (error) {
  const failure = {
    error: String(error),
    stack: error instanceof Error ? error.stack : undefined,
  };
  await writeFile(
    join(output, "failure.json"),
    JSON.stringify(failure, null, 2),
  );
  console.error(failure.error);
  process.exitCode = 2;
}
