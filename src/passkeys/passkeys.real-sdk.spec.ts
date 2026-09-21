import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

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

// NOTE: `@simplewebauthn/server` is deliberately NOT mocked here. Responses
// come from a node:crypto software authenticator and are checked by the real
// library — attestation parsing, COSE key, ES256 signature, rpID hash, origin.

const completeLogin = vi.hoisted(() => vi.fn());

vi.mock("../services/auth.service", () => ({ authService: { completeLogin } }));

import { InvalidPasskeyError } from "../errors/invalid-passkey.error";
import { InMemoryModel, resetTables, tables } from "../test-support/in-memory-cascade";
import { SoftwareAuthenticator } from "../test-support/software-authenticator";
import {
  generatePasskeyAuthenticationOptions,
  verifyPasskeyAuthentication,
} from "./passkey-authentication";
import {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
} from "./passkey-registration";
import { defined } from "../test-support/defined";
import { loadSimpleWebAuthn } from "./simplewebauthn";

class User extends InMemoryModel {
  public static table = "users";

  public get userType() {
    return "user";
  }
}

const ORIGIN = "https://app.test";
const RP_ID = "app.test";

const request = (origin: string) => ({ origin }) as never;

// Load the real optional peer before individual test budgets begin. The passkey
// methods deliberately lazy-load it in production, but paying that cold import
// in the first registration test can leave its timed-out work contaminating
// the following case.
beforeAll(async () => {
  await loadSimpleWebAuthn();
});

beforeEach(() => {
  resetTables();
  for (const key of Object.keys(configValues)) delete configValues[key];
  Object.assign(configValues, {
    "auth.passkeys": { rpID: RP_ID, rpName: "App", origin: ORIGIN },
    "auth.userType.user": User,
  });

  vi.clearAllMocks();
  completeLogin.mockImplementation(async (user: unknown) => ({
    user,
    tokens: { accessToken: { token: "t" } },
  }));
});

async function registered(
  authenticator = new SoftwareAuthenticator({ rpID: RP_ID, origin: ORIGIN }),
) {
  const user = await User.create({ email: "ada@example.com" });
  const options = await generatePasskeyRegistrationOptions(user as never);

  await verifyPasskeyRegistration(
    request(ORIGIN),
    user as never,
    authenticator.register(options.challenge),
  );

  return { user, authenticator };
}

async function login(authenticator: SoftwareAuthenticator) {
  const options = await generatePasskeyAuthenticationOptions();

  return verifyPasskeyAuthentication(
    request(ORIGIN),
    authenticator.authenticate(options.challenge),
  );
}

describe("passkeys against the real @simplewebauthn/server", () => {
  it("registers a software ES256 credential with 'none' attestation and stores its public key", async () => {
    const { user, authenticator } = await registered();
    const row = defined(tables.get("passkey_credentials")?.[0], "row");

    expect(row).toMatchObject({ credential_id: authenticator.id, counter: 0, user_id: user.id });
    expect(String(row.public_key).length).toBeGreaterThan(40);
  });

  it("logs in with a real signed assertion and stores the advanced counter", async () => {
    const { user, authenticator } = await registered();
    authenticator.counter = 1;

    await login(authenticator);

    expect(defined(tables.get("passkey_credentials")?.[0], "row").counter).toBe(1);
    expect((defined(completeLogin.mock.calls[0], "first call")[0] as User).id).toBe(user.id);
  });

  it("rejects a cloned authenticator whose counter did not advance", async () => {
    const { authenticator } = await registered();
    authenticator.counter = 3;
    await login(authenticator);

    const error = await login(authenticator).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidPasskeyError);
    expect(error.reason).toBe("counter-regression");
    expect(defined(tables.get("passkey_credentials")?.[0], "row").counter).toBe(3);
    expect(completeLogin).toHaveBeenCalledTimes(1);
  });

  it("rejects an assertion signed by a different key under the registered credential id", async () => {
    const { authenticator } = await registered();
    const impostor = new SoftwareAuthenticator({ rpID: RP_ID, origin: ORIGIN });
    Object.defineProperty(impostor, "credentialId", { value: authenticator.credentialId });
    impostor.counter = 1;

    const error = await login(impostor).catch((e) => e);

    expect(error.reason).toBe("authentication-not-verified");
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("rejects a response signed for another origin even when the request Origin is allowed", async () => {
    const { authenticator } = await registered();
    const phished = new SoftwareAuthenticator({ rpID: RP_ID, origin: "https://evil.test" });
    Object.assign(phished, { privateKey: Reflect.get(authenticator, "privateKey") });
    Object.defineProperty(phished, "credentialId", { value: authenticator.credentialId });
    phished.counter = 1;

    const error = await login(phished).catch((e) => e);

    expect(error.reason).toBe("authentication-verification-failed");
  });

  it("rejects a registration whose rpID hash is for another relying party", async () => {
    const user = await User.create({ email: "ada@example.com" });
    const options = await generatePasskeyRegistrationOptions(user as never);
    const foreign = new SoftwareAuthenticator({ rpID: "evil.test", origin: ORIGIN });

    const error = await verifyPasskeyRegistration(
      request(ORIGIN),
      user as never,
      foreign.register(options.challenge),
    ).catch((e) => e);

    expect(error.reason).toBe("registration-verification-failed");
    expect(tables.get("passkey_credentials") ?? []).toHaveLength(0);
  });
});
