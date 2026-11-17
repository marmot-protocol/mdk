import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

const pluginRoot = join(import.meta.dirname, "..");

interface DeclaredMigration {
  id: string;
  doctorOnly?: boolean;
  phase?: string;
}

interface DoctorContractModule {
  stateMigrations: ReadonlyArray<{ id: string; doctorOnly?: boolean; phase?: string }>;
}

/**
 * OpenClaw refuses a plugin update when the manifest's declared Doctor
 * migrations differ from the module's in id, order, or authority, and it can
 * only inspect a declared contract if the build emitted the module where its
 * loader looks (`dist/doctor-contract-api.js`). The packaged-install
 * acceptance (`test/packaged-install.ts`) owns the host-side proof.
 */
describe("Doctor contract artifact", () => {
  it("is built where OpenClaw resolves it and matches the manifest declaration", async () => {
    const manifest = JSON.parse(await readFile(join(pluginRoot, "openclaw.plugin.json"), "utf8")) as {
      doctorContract?: { stateMigrations?: DeclaredMigration[] };
    };
    const declared = manifest.doctorContract?.stateMigrations;
    expect(Array.isArray(declared)).toBe(true);

    const built = (await import(
      pathToFileURL(join(pluginRoot, "dist", "doctor-contract-api.js")).href
    )) as DoctorContractModule;
    expect(
      built.stateMigrations.map(({ id, doctorOnly, phase }) => ({
        id,
        ...(doctorOnly === true ? { doctorOnly } : {}),
        ...(phase !== undefined ? { phase } : {}),
      })),
    ).toEqual(declared);
  });
});
