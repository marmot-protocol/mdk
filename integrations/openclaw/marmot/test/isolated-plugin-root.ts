import { cp, mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/**
 * Materialize a process-owned plugin root for OpenClaw's loader.
 *
 * The assigned worktree may have a different uid than the test process; the
 * loader treats that as suspicious ownership. The owned entry re-exports the
 * built checkout plugin so the host exercises the packaged JavaScript entry
 * contract without depending on its TypeScript loader.
 */
export async function materializeOwnedPluginRoot(workspaceDir: string): Promise<string> {
  const source = join(import.meta.dirname, "..");
  const isolated = join(workspaceDir, "owned-marmot-plugin");
  await mkdir(join(isolated, "dist"), { recursive: true, mode: 0o700 });
  await cp(join(source, "package.json"), join(isolated, "package.json"));
  await cp(join(source, "openclaw.plugin.json"), join(isolated, "openclaw.plugin.json"));
  await writeFile(
    join(isolated, "dist", "index.js"),
    `export { default } from ${JSON.stringify(pathToFileURL(join(source, "dist", "index.js")).href)};\n`,
    { mode: 0o600 },
  );
  await writeFile(
    join(isolated, "dist", "setup-entry.js"),
    `export { default } from ${JSON.stringify(pathToFileURL(join(source, "dist", "setup-entry.js")).href)};\n`,
    { mode: 0o600 },
  );
  await symlink(join(source, "node_modules"), join(isolated, "node_modules"));
  return isolated;
}
