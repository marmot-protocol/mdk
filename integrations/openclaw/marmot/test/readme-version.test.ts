import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as {
  devDependencies?: { openclaw?: string };
  peerDependencies: { openclaw: string };
  openclaw: { install: { minHostVersion: string }; compat: { pluginApi: string } };
};
const pinnedOpenClaw = pkg.devDependencies?.openclaw;
if (!pinnedOpenClaw) {
  throw new Error("package.json must pin openclaw in devDependencies");
}

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const pinnedLabel = `openclaw@${pinnedOpenClaw}`;

describe("OpenClaw release configuration", () => {
  it("documents the pinned SDK version from package.json", () => {
    expect(readme).toContain(`Pinned OpenClaw development SDK: **\`${pinnedLabel}\`**`);
  });

  it("declares the same host API floor in install, peer, and runtime metadata", () => {
    const floor = `>=${pinnedOpenClaw}`;
    expect(pkg.peerDependencies.openclaw).toBe(floor);
    expect(pkg.openclaw.install.minHostVersion).toBe(floor);
    expect(pkg.openclaw.compat.pluginApi).toBe(floor);
  });

  it("documents the OpenClaw prerequisite version from package.json", () => {
    const hostVersion = pinnedOpenClaw.replace(/-\d+$/, "");
    expect(readme).toContain(`OpenClaw host **${hostVersion} or newer**`);
    expect(readme).toContain("never installs or upgrades OpenClaw");
  });
});

// The real installer owns the version guard. A curl sentinel proves refusal
// happens before any release download or installation, without a live host.
describe("OpenClaw installer prerequisites", () => {
  function runInstaller(nodeVersion: string, hostVersion: string) {
    const root = mkdtempSync(join(tmpdir(), "marmot-installer-version-"));
    const bin = join(root, "bin");
    const marker = join(root, "download-started");
    mkdirSync(bin, { mode: 0o700 });
    for (const [name, body] of Object.entries({
      node: 'printf "%s\\n" "$TEST_NODE_VERSION"',
      openclaw: 'printf "%s\\n" "$TEST_OPENCLAW_VERSION"',
      curl: ': > "$TEST_DOWNLOAD_MARKER"; exit 71',
    })) {
      writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`, { mode: 0o700 });
    }
    try {
      const result = spawnSync("bash", [
        fileURLToPath(new URL("../../../../scripts/install-openclaw-marmot.sh", import.meta.url)),
        "--yes", "--no-configure-openclaw", "--no-service",
      ], {
        encoding: "utf8",
        env: {
          TMPDIR: root,
          PATH: `${bin}:${process.env.PATH}`,
          HOME: root,
          OPENCLAW_HOME: root,
          MARMOT_HOME: join(root, "marmot"),
          MARMOT_INSTALL_PREFIX: join(root, "install"),
          WN_AGENT_VERSION: "9.9.9",
          TEST_NODE_VERSION: nodeVersion,
          TEST_OPENCLAW_VERSION: hostVersion,
          TEST_DOWNLOAD_MARKER: marker,
        },
      });
      return { status: result.status, stderr: result.stderr, downloadStarted: existsSync(marker) };
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  it.each(["v22.19.0", "v24.15.0", "v25.0.0", "v26.0.0", "unknown"])(
    "refuses unsupported Node %s before downloading", (version) => {
      const result = runInstaller(version, "OpenClaw 2026.10.10");
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("Node 24.16+ (24.x) or 26.1+ is required");
      expect(result.downloadStarted).toBe(false);
    },
  );

  it.each(["2026.7.1", "2026.10.9", "2026.10.10-beta.1", "unknown"])(
    "refuses unsupported OpenClaw %s before downloading", (version) => {
      const result = runInstaller("v24.16.0", `OpenClaw ${version}`);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("OpenClaw 2026.10.10 or newer is required");
      expect(result.downloadStarted).toBe(false);
    },
  );

  it.each([
    ["v24.16.0", "2026.10.10"],
    ["v26.1.0", "2026.10.10"],
    ["v24.22.1", "2026.10.10-1"],
    ["v24.22.1", "2026.10.11"],
  ])("accepts supported Node %s and OpenClaw %s", (node, host) => {
    const result = runInstaller(node, `OpenClaw ${host}`);
    expect(result.status).toBe(71);
    expect(result.downloadStarted).toBe(true);
  });
});
