import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

// The SDK boundary is mocked so each branch of auth's own logic (counter
// values, verification outcomes) is driven directly. The real library is
// exercised end to end in passkeys.real-sdk.spec.ts.
const webauthn = vi.hoisted(() => ({
  generateRegistrationOptions: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
  generateAuthenticationOptions: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
}));

vi.mock("@simplewebauthn/server", () => webauthn);

const completeLogin = vi.hoisted(() => vi.fn());

vi.mock("../services/auth.service", () => ({ authService: { completeLogin } }));

import { InvalidPasskeyError } from "../errors/invalid-passkey.error";
import { InMemoryModel, resetTables, tables } from "../test-support/in-memory-cascade";
import {
  generatePasskeyAuthenticationOptions,
  verifyPasskeyAuthentication,
} from "./passkey-authentication";
import {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
} from "./passkey-registration";
import type { PasskeyResponseJSON } from "./simplewebauthn";

class User extends InMemoryModel {
  public static table = "users";

  public get userType() {
    return "user";
  }
}

const ORIGIN = "https://app.test";

let challengeCounter = 0;

function credentialResponse(challenge: string, id = "cred-1"): PasskeyResponseJSON {
  return {
    id,
    rawId: id,
    type: "public-key",
    response: {
      clientDataJSON: Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN }),
      ).toString("base64url"),
    },
  };
}

const request = (origin: string | undefined) => ({ origin }) as never;

beforeEach(() => {
  resetTables();
  for (const key of Object.keys(configValues)) delete configValues[key];
  Object.assign(configValues, {
    "auth.passkeys": { rpID: "app.test", rpName: "App", origin: ORIGIN },
    "auth.userType.user": User,
  });

  vi.clearAllMocks();
  completeLogin.mockImplementation(async (user: unknown) => ({
    user,
    tokens: { accessToken: { token: "t" } },
  }));

  webauthn.generateRegistrationOptions.mockImplementation(async () => ({
    challenge: `reg-${++challengeCounter}`,
  }));
  webauthn.generateAuthenticationOptions.mockImplementation(async () => ({
    challenge: `auth-${++challengeCounter}`,
  }));
  webauthn.verifyRegistrationResponse.mockResolvedValue({
    verified: true,
    registrationInfo: {
      credential: {
        id: "cred-1",
        publicKey: new Uint8Array([1, 2, 3]),
        counter: 0,
        transports: ["internal"],
      },
    },
  });
  webauthn.verifyAuthenticationResponse.mockResolvedValue({
    verified: true,
    authenticationInfo: { newCounter: 6 },
  });
});

async function registeredCredential(counter: number) {
  const user = await User.create({ email: "ada@example.com" });
  tables.set("passkey_credentials", [
    {
      id: 500,
      credential_id: "cred-1",
      public_key: Buffer.from([1, 2, 3]).toString("base64url"),
      counter,
      transports: ["internal"],
      user_id: user.id,
      user_type: "user",
    },
  ]);

  return user;
}

describe("passkey registration", () => {
  it("stores the challenge hashed and user-bound, then stores the verified credential", async () => {
    const user = await User.create({ email: "ada@example.com" });

    const options = await generatePasskeyRegistrationOptions(user as never);
    const [row] = tables.get("one_time_tokens")!;

    expect(row.token_hash).toBe(createHash("sha256").update(options.challenge).digest("hex"));
    expect(row).toMatchObject({
      purpose: "passkey-registration",
      user_id: user.id,
      consumed_at: null,
    });

    const saved = await verifyPasskeyRegistration(
      request(ORIGIN),
      user as never,
      credentialResponse(options.challenge),
    );

    expect(webauthn.verifyRegistrationResponse).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedChallenge: options.challenge,
        expectedOrigin: [ORIGIN],
        expectedRPID: "app.test",
      }),
    );
    expect(saved.get("credential_id")).toBe("cred-1");
    expect(tables.get("passkey_credentials")![0]).toMatchObject({
      counter: 0,
      public_key: "AQID",
      user_id: user.id,
    });
  });

  it("rejects a challenge that was issued to a different user", async () => {
    const owner = await User.create({ email: "ada@example.com" });
    const other = await User.create({ email: "eve@example.com" });
    const options = await generatePasskeyRegistrationOptions(owner as never);

    const error = await verifyPasskeyRegistration(
      request(ORIGIN),
      other as never,
      credentialResponse(options.challenge),
    ).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidPasskeyError);
    expect(error.reason).toBe("challenge-issued-to-another-user");
    expect(tables.get("passkey_credentials") ?? []).toHaveLength(0);
  });
});

describe("passkey authentication", () => {
  it("verifies, advances the counter and finishes through completeLogin", async () => {
    const user = await registeredCredential(5);
    const options = await generatePasskeyAuthenticationOptions();

    const result = await verifyPasskeyAuthentication(
      request(ORIGIN),
      credentialResponse(options.challenge),
    );

    expect(tables.get("passkey_credentials")![0].counter).toBe(6);
    expect(completeLogin).toHaveBeenCalledTimes(1);
    expect((completeLogin.mock.calls[0][0] as User).id).toBe(user.id);
    expect(result.tokens.accessToken.token).toBe("t");
  });

  it("a challenge is single-use — the replay is rejected even though the first use succeeded", async () => {
    await registeredCredential(5);
    const options = await generatePasskeyAuthenticationOptions();
    await verifyPasskeyAuthentication(request(ORIGIN), credentialResponse(options.challenge));
    webauthn.verifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 7 },
    });

    const error = await verifyPasskeyAuthentication(
      request(ORIGIN),
      credentialResponse(options.challenge),
    ).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidPasskeyError);
    expect(completeLogin).toHaveBeenCalledTimes(1);
  });

  it("a challenge is burned by a FAILED verification too", async () => {
    await registeredCredential(5);
    const options = await generatePasskeyAuthenticationOptions();
    webauthn.verifyAuthenticationResponse.mockRejectedValueOnce(new Error("bad signature"));

    await expect(
      verifyPasskeyAuthentication(request(ORIGIN), credentialResponse(options.challenge)),
    ).rejects.toBeInstanceOf(InvalidPasskeyError);

    const error = await verifyPasskeyAuthentication(
      request(ORIGIN),
      credentialResponse(options.challenge),
    ).catch((e) => e);

    expect(error.reason).toBe("unknown-or-expired-challenge");
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("rejects an expired challenge", async () => {
    await registeredCredential(5);
    const options = await generatePasskeyAuthenticationOptions();
    tables.get("one_time_tokens")![0].expires_at = new Date(Date.now() - 1000);

    const error = await verifyPasskeyAuthentication(
      request(ORIGIN),
      credentialResponse(options.challenge),
    ).catch((e) => e);

    expect(error.reason).toBe("unknown-or-expired-challenge");
  });

  it.each([
    ["a counter that went backwards", 5, 4],
    ["a counter that did not move", 5, 5],
  ])(
    "rejects %s (cloned authenticator) and keeps the stored counter",
    async (_label, stored, presented) => {
      await registeredCredential(stored);
      const options = await generatePasskeyAuthenticationOptions();
      webauthn.verifyAuthenticationResponse.mockResolvedValue({
        verified: true,
        authenticationInfo: { newCounter: presented },
      });

      const error = await verifyPasskeyAuthentication(
        request(ORIGIN),
        credentialResponse(options.challenge),
      ).catch((e) => e);

      expect(error).toBeInstanceOf(InvalidPasskeyError);
      expect(error.reason).toBe("counter-regression");
      expect(tables.get("passkey_credentials")![0].counter).toBe(stored);
      expect(completeLogin).not.toHaveBeenCalled();
    },
  );

  it("allows a 0 → 0 counter (authenticators that do not count)", async () => {
    await registeredCredential(0);
    const options = await generatePasskeyAuthenticationOptions();
    webauthn.verifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 0 },
    });

    await verifyPasskeyAuthentication(request(ORIGIN), credentialResponse(options.challenge));

    expect(completeLogin).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["a foreign Origin", "https://evil.test"],
    ["no Origin header", undefined],
  ])("rejects %s before consuming the challenge (CSRF rule)", async (_label, origin) => {
    await registeredCredential(5);
    const options = await generatePasskeyAuthenticationOptions();

    const error = await verifyPasskeyAuthentication(
      request(origin),
      credentialResponse(options.challenge),
    ).catch((e) => e);

    expect(error.reason).toBe("origin-mismatch");
    expect(webauthn.verifyAuthenticationResponse).not.toHaveBeenCalled();
    expect(tables.get("one_time_tokens")![0].consumed_at).toBeNull();
  });

  it("rejects an unknown credential", async () => {
    await registeredCredential(5);
    const options = await generatePasskeyAuthenticationOptions();

    const error = await verifyPasskeyAuthentication(
      request(ORIGIN),
      credentialResponse(options.challenge, "nope"),
    ).catch((e) => e);

    expect(error.reason).toBe("unknown-credential");
  });
});
