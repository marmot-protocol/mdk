import { cp, mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/**
 * Materialize a process-owned plugin root for OpenClaw's loader.
 *
 * The assigned worktree may have a different uid than the test process; the
 * loader treats that as suspicious ownership. The owned entry re-exports the
 * checkout plugin so gateway/runtime state stays the same module instance the
 * tests observe.
 */
export async function materializeOwnedPluginRoot(workspaceDir: string): Promise<string> {
  const source = join(import.meta.dirname, "..");
  const isolated = join(workspaceDir, "owned-marmot-plugin");
  await mkdir(isolated, { recursive: true, mode: 0o700 });
  await cp(join(source, "package.json"), join(isolated, "package.json"));
  await cp(join(source, "openclaw.plugin.json"), join(isolated, "openclaw.plugin.json"));
  await writeFile(
    join(isolated, "index.ts"),
    `export { default } from ${JSON.stringify(pathToFileURL(join(source, "index.ts")).href)};\n`,
    { mode: 0o600 },
  );
  await writeFile(
    join(isolated, "setup-entry.ts"),
    `export { default } from ${JSON.stringify(pathToFileURL(join(source, "setup-entry.ts")).href)};\n`,
    { mode: 0o600 },
  );
  await symlink(join(source, "node_modules"), join(isolated, "node_modules"));
  return isolated;
}
