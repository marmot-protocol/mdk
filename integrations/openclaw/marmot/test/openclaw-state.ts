import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";

// Real host queues and session helpers must never read or write an operator's
// OpenClaw home. Vitest loads this before importing each test's host SDK.
const root = mkdtempSync(join(tmpdir(), "marmot-openclaw-state-"));
const previousHome = process.env.OPENCLAW_HOME;
const previousState = process.env.OPENCLAW_STATE_DIR;
process.env.OPENCLAW_HOME = join(root, "home");
process.env.OPENCLAW_STATE_DIR = join(root, "state");
afterAll(() => {
  if (previousHome === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = previousHome;
  if (previousState === undefined) delete process.env.OPENCLAW_STATE_DIR;
  else process.env.OPENCLAW_STATE_DIR = previousState;
  rmSync(root, { recursive: true, force: true });
});
