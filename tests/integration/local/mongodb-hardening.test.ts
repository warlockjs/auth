import { vi } from "vitest";
import { hasLocalMongodb, startLocalMongodb } from "../helpers/local-database-harness";
import { defineAuthHardeningSuite } from "./hardening-suite";

/**
 * Local MongoDB run of the auth hardening suite. Skips unless
 * `LOCAL_MONGO_URI` and `LOCAL_MONGO_DATABASE` are set, e.g.:
 *
 *   LOCAL_MONGO_URI=mongodb://127.0.0.1:27017 LOCAL_MONGO_DATABASE=auth_itest \
 *     vitest run --config vitest.integration.config.ts tests/integration/local
 */
const configValues = vi.hoisted(() => ({}) as Record<string, unknown>);

vi.mock("@warlock.js/core", async () =>
  (await import("../../../src/test-support/fake-core")).fakeCoreModule(configValues),
);

defineAuthHardeningSuite("MongoDB", {
  available: hasLocalMongodb(),
  start: startLocalMongodb,
  configValues,
});
