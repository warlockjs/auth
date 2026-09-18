import { afterEach, describe, expect, it, vi } from "vitest";

const configValues = vi.hoisted(() => ({}) as Record<string, unknown>);

vi.mock("@warlock.js/core", async () =>
  (await import("../test-support/fake-core")).fakeCoreModule(configValues),
);
vi.mock(
  "@warlock.js/cascade",
  async () => (await import("../test-support/in-memory-cascade")).cascadeModule,
);
vi.mock(
  "@warlock.js/seal",
  async () => (await import("../test-support/in-memory-cascade")).sealModule,
);
vi.mock("@warlock.js/logger", () => ({ log: { warn: vi.fn(), error: vi.fn() } }));
vi.mock("../services/auth.service", () => ({ authService: { completeLogin: vi.fn() } }));

import { resolveAuthProvider } from "./provider-login";

afterEach(() => {
  for (const key of Object.keys(configValues)) delete configValues[key];
});

describe("resolveAuthProvider — the provider name comes from a URL", () => {
  it.each(["constructor", "toString", "hasOwnProperty", "__proto__", "valueOf"])(
    "refuses the Object.prototype name %s instead of resolving it as a provider",
    (name) => {
      configValues["auth.providers.custom"] = {};

      expect(() => resolveAuthProvider(name)).toThrow(`no login provider "${name}"`);
    },
  );

  it("still resolves an app-registered custom provider", () => {
    const provider = { name: "acme" };

    configValues["auth.providers.custom"] = { acme: provider };

    expect(resolveAuthProvider("acme")).toBe(provider);
  });
});
