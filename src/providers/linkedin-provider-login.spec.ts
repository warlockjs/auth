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
// signature / iss / aud / exp checks all run through jose itself.
vi.mock("jose", async () => {
  const { readdirSync } = await import("node:fs");
  const { resolve } = await import("node:path");
  const { pathToFileURL } = await import("node:url");
  const store = resolve(__dirname, "../../../node_modules/.pnpm");
  const entry = readdirSync(store).find((name) => name.startsWith("jose@"));

  if (!entry) {
    throw new Error(
      `linkedin-provider-login.spec needs jose under ${store} to sign test id_tokens.`,
    );
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

const CLIENT_ID = "linkedin-client-123";
const ISSUER = "https://www.linkedin.com/oauth";

type TestJose = {
  generateKeyPair: (alg: string) => Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }>;
  exportJWK: (key: CryptoKey) => Promise<Record<string, unknown>>;
  createLocalJWKSet: (jwks: { keys: Record<string, unknown>[] }) => unknown;
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
let signingKey: CryptoKey;

beforeAll(async () => {
  jose = (await import(JOSE)) as TestJose;
  const pair = await jose.generateKeyPair("RS256");
  signingKey = pair.privateKey;

  const jwk = { ...(await jose.exportJWK(pair.publicKey)), kid: "k1", alg: "RS256" };
  keys.resolver = jose.createLocalJWKSet({ keys: [jwk] });
});

type Claims = Record<string, unknown>;

async function idToken(
  claims: Claims,
  options: { key?: CryptoKey; audience?: string; issuer?: string; expiresAt?: number } = {},
) {
  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime(options.expiresAt ?? Math.floor(Date.now() / 1000) + 300)
    .sign(options.key ?? signingKey);
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
    clearCookie: vi.fn((name: string) => cookies.delete(name)),
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
  const url = new URL(await startProviderLogin(response as never, "linkedin"));
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
    "linkedin",
    fakeRequest(cookie, query) as never,
    response as never,
  );
}

beforeEach(() => {
  resetTables();
  for (const key of Object.keys(configValues)) delete configValues[key];
  Object.assign(configValues, {
    "auth.accessToken.secret": "test-secret",
    "auth.providers.linkedin": {
      clientId: CLIENT_ID,
      clientSecret: "shh",
      redirectUri: "https://app.test/auth/linkedin/callback",
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
  sub: "linkedin-sub-1",
  email: "ada@example.com",
  email_verified: true,
  name: "Ada",
  nonce,
});

describe("startProviderLogin (linkedin)", () => {
  it("redirects with state, nonce and an S256 PKCE challenge, and stores them in a short-lived signed cookie", async () => {
    const { url, cookie } = await startLogin();

    expect(url.origin + url.pathname).toBe("https://www.linkedin.com/oauth/v2/authorization");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("openid profile email");
    expect(cookie.options).toMatchObject({ raw: true, path: "/", maxAge: 600 });
  });
});

describe("completeProviderLogin (linkedin)", () => {
  it("exchanges the code with the cookie's PKCE verifier, verifies the id_token, creates + links a verified user, and finishes through completeLogin", async () => {
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce));

    const result = await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tokenEndpoint.calls).toHaveLength(1);
    expect(tables.get("users")).toHaveLength(1);
    expect(tables.get("users")![0]).toMatchObject({ email: "ada@example.com", name: "Ada" });
    expect(tables.get("provider_accounts")![0]).toMatchObject({
      provider: "linkedin",
      provider_user_id: "linkedin-sub-1",
      user_type: "user",
    });
    expect(completeLogin).toHaveBeenCalledTimes(1);
    expect(result.tokens.accessToken.token).toBe("t");
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
    await User.create({ email: "ada@example.com" });
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

  it("links a verified email to the existing account instead of creating one", async () => {
    const existing = await User.create({ email: "ada@example.com" });
    const login = await startLogin();
    tokenEndpoint.idToken = await idToken(verifiedClaims(login.nonce));

    await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tables.get("users")).toHaveLength(1);
    expect(defined(tables.get("provider_accounts")?.[0], "row").user_id).toBe(existing.id);
    expect((defined(completeLogin.mock.calls[0], "first call")[0] as User).id).toBe(existing.id);
  });
});
