import { describe, expect, it, vi } from "vitest";

const configValues = vi.hoisted(() => ({}) as Record<string, unknown>);

// Neither SDK can be loaded in this file — the shape Node reports for an app
// that never ran the matching `warlock add`.
vi.mock("jose", () => {
  throw Object.assign(new Error("Cannot find package 'jose' imported from app"), {
    code: "ERR_MODULE_NOT_FOUND",
  });
});
vi.mock("@simplewebauthn/server", () => {
  throw Object.assign(new Error("Cannot find package '@simplewebauthn/server' imported from app"), {
    code: "ERR_MODULE_NOT_FOUND",
  });
});

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
vi.mock("./auth.service", () => ({ authService: { completeLogin: vi.fn() } }));

import { AuthProviderSdkMissingError } from "../errors/auth-provider-sdk-missing.error";
import { generatePasskeyAuthenticationOptions } from "../passkeys/passkey-authentication";
import { GoogleProvider } from "../providers/google-provider";
import { loadOptionalPeer } from "./optional-peer";

describe("login methods without their optional SDK", () => {
  it("Google throws AuthProviderSdkMissingError naming jose and `warlock add auth-google`, before any network call", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const provider = new GoogleProvider({
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://app.test/cb",
    });
    const expected = { state: "s", nonce: "n", codeVerifier: "v" };
    const error = await provider.handleCallback({ query: { code: "x" }, expected }).catch((e) => e);

    expect(error).toBeInstanceOf(AuthProviderSdkMissingError);
    expect(error.message).toContain('"jose"');
    expect(error.message).toContain("warlock add auth-google");
    expect(fetchSpy).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("passkeys throw AuthProviderSdkMissingError naming @simplewebauthn/server and `warlock add auth-passkeys`", async () => {
    const error = await generatePasskeyAuthenticationOptions().catch((e) => e);

    expect(error).toBeInstanceOf(AuthProviderSdkMissingError);
    expect(error.message).toContain('"@simplewebauthn/server"');
    expect(error.message).toContain("warlock add auth-passkeys");
  });

  it("rethrows a missing TRANSITIVE dependency untouched", async () => {
    vi.doMock("some-sdk", () => {
      throw Object.assign(new Error("Cannot find package 'left-pad' imported from some-sdk"), {
        code: "ERR_MODULE_NOT_FOUND",
      });
    });

    const error = await loadOptionalPeer("some-sdk", "some-feature").catch((e) => e);

    expect(error).not.toBeInstanceOf(AuthProviderSdkMissingError);
    // vitest wraps a throwing mock factory; the original resolver error is the cause.
    expect(`${error.message} ${error.cause?.message}`).toContain("left-pad");
  });
});
