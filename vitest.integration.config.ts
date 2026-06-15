import { resolve } from "node:path";
import { defineConfig } from "vitest/config";
import baseConfig from "./vitest.config";

/**
 * Integration-scoped vitest config for `@warlock.js/auth`.
 *
 * Reuses the base config's `@warlock.js/*` source aliases (so the token models
 * resolve against the sibling package sources, not a stale build) but narrows
 * the run to `tests/integration/**` and grants the long timeouts a real
 * Postgres container needs — a cold `postgres:16-alpine` boot can take ~50s on
 * first pull.
 *
 * It is OPT-IN: the default `vitest run` only globs `src/**\/*.spec.ts`, so a
 * machine without Docker still gets a fully green unit suite. Run this layer
 * explicitly (Docker must be running):
 *
 *   npx vitest run --config vitest.integration.config.ts
 */
export default defineConfig({
  resolve: {
    alias: {
      // Reuse the base `@warlock.js/*` source aliases, plus `@warlock.js/context`
      // — a transitive dependency of cascade's source that the mocked unit suite
      // never loads, so it is absent from the base config.
      ...(baseConfig.resolve?.alias as Record<string, string>),
      "@warlock.js/context": resolve(__dirname, "../context/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    globals: false,
    include: ["tests/integration/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    testTimeout: 120000,
    hookTimeout: 120000,
  },
});
