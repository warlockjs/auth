import { createHash } from "node:crypto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const configValues = vi.hoisted(() => ({}) as Record<string, unknown>);
const keys = vi.hoisted(() => ({ resolver: undefined as unknown }));

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

// The REAL jose, loaded from the workspace store (it is not linked into auth's
// node_modules). Only `createRemoteJWKSet` is swapped, for a local key set, so
// signature / iss / aud / exp checks on the id_token all run through jose
// itself — and the client-secret JWT this provider signs is verified below
// with `jose.jwtVerify` against the matching public key, so the ES256 signer
// is proven too, not just format-checked.
vi.mock("jose", async () => {
  const { readdirSync } = await import("node:fs");
  const { resolve } = await import("node:path");
  const { pathToFileURL } = await import("node:url");
  const store = resolve(__dirname, "../../../node_modules/.pnpm");
  const entry = readdirSync(store).find((name) => name.startsWith("jose@"));

  if (!entry) {
    throw new Error(`apple-provider-login.spec needs jose under ${store} to sign test id_tokens.`);
  }

  const real = await import(
    pathToFileURL(resolve(store, entry, "node_modules/jose/dist/webapi/index.js")).href
  );

  return {
    ...real,
    createRemoteJWKSet: () => (header: unknown, token: unknown) =>
      (keys.resolver as (header: unknown, token: unknown) => unknown)(header, token),
  };
});

const completeLogin = vi.hoisted(() => vi.fn());

vi.mock("../services/auth.service", () => ({ authService: { completeLogin } }));

import { InMemoryModel, resetTables, tables } from "../test-support/in-memory-cascade";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { ProviderEmailNotVerifiedError } from "../errors/provider-email-not-verified.error";
import { completeProviderLogin, startProviderLogin } from "./provider-login";
import { PROVIDER_STATE_COOKIE } from "./provider-state-cookie";
import { defined } from "../test-support/defined";

class User extends InMemoryModel {
  public static table = "users";

  public get userType() {
    return "user";
  }
}

const CLIENT_ID = "com.example.app";
const TEAM_ID = "TEAM1234AB";
const KEY_ID = "KEY1234CD";
const ISSUER = "https://appleid.apple.com";

type TestJose = {
  generateKeyPair: (
    alg: string,
    options?: { extractable?: boolean },
  ) => Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }>;
  exportJWK: (key: CryptoKey) => Promise<Record<string, unknown>>;
  exportPKCS8: (key: CryptoKey) => Promise<string>;
  createLocalJWKSet: (jwks: { keys: Record<string, unknown>[] }) => unknown;
  jwtVerify: (
    token: string,
    key: unknown,
    options: { issuer: string; audience: string },
  ) => Promise<{ payload: Record<string, unknown>; protectedHeader: Record<string, unknown> }>;
  SignJWT: new (claims: Record<string, unknown>) => {
    setProtectedHeader: (header: Record<string, unknown>) => TestJoseBuilder;
  };
};

type TestJoseBuilder = {
  setIssuer: (issuer: string) => TestJoseBuilder;
  setAudience: (audience: string) => TestJoseBuilder;
  setIssuedAt: () => TestJoseBuilder;
  setExpirationTime: (seconds: number) => TestJoseBuilder;
  sign: (key: CryptoKey) => Promise<string>;
};

const JOSE: string = "jose";

let jose: TestJose;
let appleSigningKey: CryptoKey;
let appPrivateKey: CryptoKey;
let appPublicKey: CryptoKey;
let appPrivateKeyPem: string;

beforeAll(async () => {
  jose = (await import(JOSE)) as TestJose;

  const applePair = await jose.generateKeyPair("ES256");
  appleSigningKey = applePair.privateKey;
  const jwk = { ...(await jose.exportJWK(applePair.publicKey)), kid: "k1", alg: "ES256" };
  keys.resolver = jose.createLocalJWKSet({ keys: [jwk] });

  const appPair = await jose.generateKeyPair("ES256", { extractable: true });
  appPrivateKey = appPair.privateKey;
  appPublicKey = appPair.publicKey;
  appPrivateKeyPem = await jose.exportPKCS8(appPrivateKey);
});

type Claims = Record<string, unknown>;

async function idToken(
  claims: Claims,
  options: { key?: CryptoKey; audience?: string; issuer?: string; expiresAt?: number } = {},
) {
  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: "k1" })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime(options.expiresAt ?? Math.floor(Date.now() / 1000) + 300)
    .sign(options.key ?? appleSigningKey);
}

const tokenEndpoint = {
  challengeForCode: new Map<string, string>(),
  idToken: "" as string,
  calls: [] as URLSearchParams[],
};

function fakeResponse() {
  const cookies = new Map<string, { value: string; options: Record<string, unknown> }>();

  return {
    cookies,
    cookie: vi.fn((name: string, value: string, options: Record<string, unknown>) => {
      cookies.set(name, { value, options });
    }),
    clearCookie: vi.fn((name: string, options: Record<string, unknown>) => {
      cookies.delete(name);
      return options;
    }),
  };
}

function fakeRequest(cookie: string | undefined, query: Record<string, unknown>) {
  return {
    cookie: (name: string) => (name === PROVIDER_STATE_COOKIE ? cookie : undefined),
    input: (key: string) => query[key],
  };
}

async function startLogin() {
  const response = fakeResponse();
  const url = new URL(await startProviderLogin(response as never, "apple"));
  const params = url.searchParams;
  const code = `code-${Math.random()}`;

  tokenEndpoint.challengeForCode.set(code, params.get("code_challenge")!);

  return {
    url,
    code,
    state: params.get("state")!,
    nonce: params.get("nonce")!,
    cookie: response.cookies.get(PROVIDER_STATE_COOKIE)!,
  };
}

async function callback(cookie: string | undefined, query: Record<string, unknown>) {
  const response = fakeResponse();

  return completeProviderLogin(
    User as never,
    "apple",
    fakeRequest(cookie, query) as never,
    response as never,
  );
}

/** Like {@link callback}, but also hands back the fake response, to inspect `clearCookie`'s attrs. */
async function callbackWithResponse(cookie: string | undefined, query: Record<string, unknown>) {
  const response = fakeResponse();

  const result = await completeProviderLogin(
    User as never,
    "apple",
    fakeRequest(cookie, query) as never,
    response as never,
  );

  return { result, response };
}

beforeEach(() => {
  resetTables();
  for (const key of Object.keys(configValues)) delete configValues[key];
  Object.assign(configValues, {
    "auth.accessToken.secret": "test-secret",
    "auth.providers.apple": {
      clientId: CLIENT_ID,
      teamId: TEAM_ID,
      keyId: KEY_ID,
      privateKey: appPrivateKeyPem,
      redirectUri: "https://app.test/auth/apple/callback",
    },
  });

  completeLogin.mockReset();
  completeLogin.mockImplementation(async (user: unknown) => ({
    user,
    tokens: { accessToken: { token: "t" } },
  }));

  tokenEndpoint.challengeForCode.clear();
  tokenEndpoint.calls = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init: { body: URLSearchParams }) => {
      const body = new URLSearchParams(init.body);
      tokenEndpoint.calls.push(body);
      const expected = tokenEndpoint.challengeForCode.get(body.get("code") ?? "");
      const actual = createHash("sha256")
        .update(body.get("code_verifier") ?? "")
        .digest("base64url");

      if (!expected || expected !== actual) {
        return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
      }

      return new Response(JSON.stringify({ id_token: tokenEndpoint.idToken }), { status: 200 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const verifiedClaims = (nonce: string): Claims => ({
  sub: "apple-sub-1",
  email: "ada@privaterelay.appleid.com",
  email_verified: true,
  nonce,
});

describe("startProviderLogin (apple)", () => {
  it("redirects with state, nonce, an S256 PKCE challenge and form_post (name/email were requested), and stores the state in a short-lived signed cookie", async () => {
    const { url, cookie } = await startLogin();

    expect(url.origin + url.pathname).toBe("https://appleid.apple.com/auth/authorize");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("name email");
    expect(url.searchParams.get("response_mode")).toBe("form_post");
    expect(cookie.options).toMatchObject({ raw: true, path: "/", maxAge: 600 });
  });

  it("writes the state cookie SameSite=None; Secure — a Lax cookie is dropped on Apple's cross-site form_post callback", async () => {
    const { cookie } = await startLogin();

    expect(cookie.options).toMatchObject({ sameSite: "none", secure: true });
  });
});

describe("completeProviderLogin (apple)", () => {
  it("signs a real ES256 client-secret JWT (iss=teamId, sub=clientId, aud=Apple, kid=keyId) that verifies against the app's own public key", async () => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce));

    await callback(login.cookie.value, { code: login.code, state: login.state });

    const clientSecret = defined(tokenEndpoint.calls[0], "token call").get("client_secret")!;
    const { payload, protectedHeader } = await jose.jwtVerify(clientSecret, appPublicKey, {
      issuer: TEAM_ID,
      audience: ISSUER,
    });

    expect(protectedHeader.alg).toBe("ES256");
    expect(protectedHeader.kid).toBe(KEY_ID);
    expect(payload.sub).toBe(CLIENT_ID);
  });

  it("exchanges the code with the cookie's PKCE verifier, verifies the id_token, creates + links a verified user (private-relay email included), and finishes through completeLogin", async () => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce));

    const result = await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tokenEndpoint.calls).toHaveLength(1);
    expect(tables.get("users")).toHaveLength(1);
    expect(tables.get("users")![0]).toMatchObject({ email: "ada@privaterelay.appleid.com" });
    expect(tables.get("provider_accounts")![0]).toMatchObject({
      provider: "apple",
      provider_user_id: "apple-sub-1",
      user_type: "user",
    });
    expect(completeLogin).toHaveBeenCalledTimes(1);
    expect(result.tokens.accessToken.token).toBe("t");
  });

  it("reads the account name from the form_post `user` field, present only on the first authorization", async () => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce));

    await callback(login.cookie.value, {
      code: login.code,
      state: login.state,
      user: JSON.stringify({ name: { firstName: "Ada", lastName: "Lovelace" } }),
    });

    expect(tables.get("users")![0]).toMatchObject({ name: "Ada Lovelace" });
  });

  it('accepts Apple\'s string-form `email_verified: "true"`, not only the JSON boolean', async () => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken({
      ...verifiedClaims(login.nonce),
      email_verified: "true",
    });

    await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tables.get("users")).toHaveLength(1);
    expect(completeLogin).toHaveBeenCalledTimes(1);
  });

  it("rejects a state mismatch before any token exchange", async () => {
    const login = await startLogin();

    const error = await callback(login.cookie.value, { code: login.code, state: "forged" }).catch(
      (e) => e,
    );

    expect(error).toBeInstanceOf(InvalidProviderCallbackError);
    expect(error.reason).toBe("state-mismatch");
    expect(tokenEndpoint.calls).toHaveLength(0);
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("rejects when the code was bound to another login's PKCE challenge", async () => {
    const victim = await startLogin();
    const attacker = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(attacker.nonce));

    const error = await callback(attacker.cookie.value, {
      code: victim.code,
      state: attacker.state,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidProviderCallbackError);
    expect(error.reason).toBe("code-exchange-failed");
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("rejects an id_token whose nonce is not the one this login stored", async () => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims("some-other-nonce"));

    const error = await callback(login.cookie.value, {
      code: login.code,
      state: login.state,
    }).catch((e) => e);

    expect(error.reason).toBe("nonce-mismatch");
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it.each([
    ["a wrong audience", { audience: "someone-else" }],
    ["a wrong issuer", { issuer: "https://evil.example.com" }],
    ["an expired token", { expiresAt: Math.floor(Date.now() / 1000) - 3600 }],
  ])("rejects an id_token with %s", async (_label, options) => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce), options);

    const error = await callback(login.cookie.value, {
      code: login.code,
      state: login.state,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidProviderCallbackError);
    expect(error.reason).toBe("invalid-id-token");
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("never links or creates on an UNVERIFIED provider email — not even to an existing account with that email", async () => {
    await User.create({ email: "ada@privaterelay.appleid.com" });
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken({
      ...verifiedClaims(login.nonce),
      email_verified: false,
    });

    const error = await callback(login.cookie.value, {
      code: login.code,
      state: login.state,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(ProviderEmailNotVerifiedError);
    expect(tables.get("users")).toHaveLength(1);
    expect(tables.get("provider_accounts") ?? []).toHaveLength(0);
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("clears the state cookie SameSite=None; Secure — the same attrs it was written with, or the browser ignores the clear on Apple's form_post callback", async () => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce));

    const { response } = await callbackWithResponse(login.cookie.value, {
      code: login.code,
      state: login.state,
    });

    expect(response.clearCookie).toHaveBeenCalledWith(
      PROVIDER_STATE_COOKIE,
      expect.objectContaining({ path: "/", sameSite: "none", secure: true }),
    );
  });

  it("links a verified email to the existing account instead of creating one", async () => {
    const existing = await User.create({ email: "ada@privaterelay.appleid.com" });
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce));

    await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tables.get("users")).toHaveLength(1);
    expect(defined(tables.get("provider_accounts")?.[0], "row").user_id).toBe(existing.id);
    expect((defined(completeLogin.mock.calls[0], "first call")[0] as User).id).toBe(existing.id);
  });
});
