import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as {
  devDependencies?: { openclaw?: string };
};
const pinnedOpenClaw = pkg.devDependencies?.openclaw;
if (!pinnedOpenClaw) {
  throw new Error("package.json must pin openclaw in devDependencies");
}

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const pinnedLabel = `openclaw@${pinnedOpenClaw}`;

describe("README OpenClaw SDK pin", () => {
  it("documents the pinned SDK version from package.json", () => {
    expect(readme).toContain(`Pinned OpenClaw SDK: **\`${pinnedLabel}\`**`);
  });

  it("documents the OpenClaw prerequisite version from package.json", () => {
    expect(readme).toContain(`OpenClaw **${pinnedOpenClaw}** or compatible`);
    expect(readme).toContain(`this plugin pins \`${pinnedLabel}\``);
  });
});
