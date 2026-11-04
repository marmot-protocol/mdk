// OpenClaw 2026.10.10 exports this public JS subpath without declarations.
// Keep the consumed shape narrow. The runtime-surface canary checks the export,
// and outbound media tests exercise root, symlink and hard-link rejection.
declare module "openclaw/plugin-sdk/file-access-runtime" {
  export function readLocalFileFromRoots(options: {
    filePath: string;
    roots: readonly string[];
    label: string;
  }): Promise<{ buffer: import("node:buffer").Buffer } | null>;
}
