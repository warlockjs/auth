import { vi } from "vitest";
import { hasLocalPostgres, startLocalPostgres } from "../helpers/local-database-harness";
import { defineAuthHardeningSuite } from "./hardening-suite";

/**
 * Local Postgres run of the auth hardening suite. Skips unless
 * `LOCAL_PG_DATABASE`, `LOCAL_PG_USER` and `LOCAL_PG_PASSWORD` are set
 * (`LOCAL_PG_HOST` / `LOCAL_PG_PORT` default to 127.0.0.1:5432), e.g.:
 *
 *   LOCAL_PG_DATABASE=auth_itest LOCAL_PG_USER=auth LOCAL_PG_PASSWORD=secret \
 *     vitest run --config vitest.integration.config.ts tests/integration/local
 */
const configValues = vi.hoisted(() => ({}) as Record<string, unknown>);

vi.mock("@warlock.js/core", async () =>
  (await import("../../../src/test-support/fake-core")).fakeCoreModule(configValues),
);

defineAuthHardeningSuite("Postgres", {
  available: hasLocalPostgres(),
  start: startLocalPostgres,
  configValues,
});
