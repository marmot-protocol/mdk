import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    fileParallelism: process.env.MARMOT_OPENCLAW_CONNECTOR_E2E !== "1",
  },
});
