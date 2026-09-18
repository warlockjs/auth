import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

const CLIENT_ID = "x-client-123";
const CLIENT_SECRET = "x-secret-456";

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

/** An X token endpoint that enforces PKCE and Basic auth on the confidential client. */
const tokenEndpoint = {
  challengeForCode: new Map<string, string>(),
  calls: [] as { body: URLSearchParams; authorization: string | null }[],
};

/** What `/2/users/me` answers for the redeemed access token. */
const api = {
  accessToken: "x-access-token",
  user: {} as Record<string, unknown>,
  meCalls: [] as URL[],
  meAuth: [] as (string | null)[],
};

async function startLogin() {
  const response = fakeResponse();
  const url = new URL(await startProviderLogin(response as never, "x"));
  const params = url.searchParams;
  const code = `code-${Math.random()}`;

  tokenEndpoint.challengeForCode.set(code, params.get("code_challenge")!);

  return {
    url,
    code,
    state: params.get("state")!,
    cookie: response.cookies.get(PROVIDER_STATE_COOKIE)!,
  };
}

async function callback(cookie: string | undefined, query: Record<string, unknown>) {
  const response = fakeResponse();

  return completeProviderLogin(
    User as never,
    "x",
    fakeRequest(cookie, query) as never,
    response as never,
  );
}

beforeEach(() => {
  resetTables();
  for (const key of Object.keys(configValues)) delete configValues[key];
  Object.assign(configValues, {
    "auth.accessToken.secret": "test-secret",
    "auth.providers.x": {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: "https://app.test/auth/x/callback",
    },
  });

  completeLogin.mockReset();
  completeLogin.mockImplementation(async (user: unknown) => ({
    user,
    tokens: { accessToken: { token: "t" } },
  }));

  tokenEndpoint.challengeForCode.clear();
  tokenEndpoint.calls = [];
  api.user = {
    id: "x-42",
    name: "Ada",
    username: "ada",
    profile_image_url: "https://x.test/ada.png",
  };
  api.meCalls = [];
  api.meAuth = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const parsed = new URL(url);

      if (parsed.origin + parsed.pathname === "https://api.twitter.com/2/oauth2/token") {
        const headers = new Headers(init?.headers);
        const body = new URLSearchParams(init!.body as string);
        tokenEndpoint.calls.push({ body, authorization: headers.get("authorization") });
        const expected = tokenEndpoint.challengeForCode.get(body.get("code") ?? "");
        const actual = createHash("sha256")
          .update(body.get("code_verifier") ?? "")
          .digest("base64url");

        if (!expected || expected !== actual) {
          return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
        }

        return new Response(JSON.stringify({ access_token: api.accessToken }), { status: 200 });
      }

      if (parsed.origin + parsed.pathname === "https://api.twitter.com/2/users/me") {
        const headers = new Headers(init?.headers);
        api.meCalls.push(parsed);
        api.meAuth.push(headers.get("authorization"));
        return new Response(JSON.stringify({ data: api.user }), { status: 200 });
      }

      throw new Error(`unexpected fetch: ${url}`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("startProviderLogin (x)", () => {
  it("redirects with state and an S256 PKCE challenge, and stores them in a short-lived signed cookie", async () => {
    const { url, cookie } = await startLogin();

    expect(url.origin + url.pathname).toBe("https://twitter.com/i/oauth2/authorize");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("tweet.read users.read");
    expect(cookie.options).toMatchObject({ raw: true, path: "/", maxAge: 600 });
  });
});

describe("completeProviderLogin (x)", () => {
  it("exchanges the code with Basic auth and the cookie's PKCE verifier, fetches the profile, creates + links a user, and finishes through completeLogin", async () => {
    await User.create({ email: "ada@example.com" });
    const login = await startLogin();

    // X never returns an email — link an existing account by seeding the provider link directly.
    tables.set("provider_accounts", [
      {
        id: 1,
        provider: "x",
        provider_user_id: "x-42",
        user_id: defined(tables.get("users")?.[0], "row").id,
        user_type: "user",
      },
    ]);

    const result = await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tokenEndpoint.calls).toHaveLength(1);
    expect(tokenEndpoint.calls[0]!.authorization).toBe(
      `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`,
    );
    expect(api.meCalls).toHaveLength(1);
    expect(api.meAuth[0]).toBe(`Bearer ${api.accessToken}`);
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

    const error = await callback(attacker.cookie.value, {
      code: victim.code,
      state: attacker.state,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidProviderCallbackError);
    expect(error.reason).toBe("code-exchange-failed");
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("never invents an email — a first-time login without an existing link is rejected as an unverified/missing email", async () => {
    const login = await startLogin();

    const error = await callback(login.cookie.value, {
      code: login.code,
      state: login.state,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(ProviderEmailNotVerifiedError);
    expect(tables.get("users") ?? []).toHaveLength(0);
    expect(tables.get("provider_accounts") ?? []).toHaveLength(0);
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("rejects a missing access_token in an otherwise-200 token response", async () => {
    const login = await startLogin();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (new URL(url).pathname === "/2/oauth2/token") {
          return new Response(JSON.stringify({}), { status: 200 });
        }

        throw new Error(`unexpected fetch: ${url}`);
      }),
    );

    const error = await callback(login.cookie.value, {
      code: login.code,
      state: login.state,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidProviderCallbackError);
    expect(error.reason).toBe("missing-access-token");
  });
});
