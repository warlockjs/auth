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

const CLIENT_ID = "gh-client-123";

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

/** A GitHub token endpoint that, like GitHub, enforces PKCE against the challenge bound to the code. */
const tokenEndpoint = {
  challengeForCode: new Map<string, string>(),
  calls: [] as URLSearchParams[],
};

/** What `/user` and `/user/emails` answer for the redeemed access token. */
const api = {
  accessToken: "gh-access-token",
  user: {} as Record<string, unknown>,
  emails: [] as Record<string, unknown>[],
  userCalls: [] as Request[],
  emailsCalls: [] as Request[],
};

async function startLogin() {
  const response = fakeResponse();
  const url = new URL(await startProviderLogin(response as never, "github"));
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
    "github",
    fakeRequest(cookie, query) as never,
    response as never,
  );
}

beforeEach(() => {
  resetTables();
  for (const key of Object.keys(configValues)) delete configValues[key];
  Object.assign(configValues, {
    "auth.accessToken.secret": "test-secret",
    "auth.providers.github": {
      clientId: CLIENT_ID,
      clientSecret: "shh",
      redirectUri: "https://app.test/auth/github/callback",
    },
  });

  completeLogin.mockReset();
  completeLogin.mockImplementation(async (user: unknown) => ({
    user,
    tokens: { accessToken: { token: "t" } },
  }));

  tokenEndpoint.challengeForCode.clear();
  tokenEndpoint.calls = [];
  api.user = { id: 555, login: "ada-dev", name: "Ada", avatar_url: "https://gh.test/ada.png" };
  api.emails = [{ email: "ada@example.com", primary: true, verified: true }];
  api.userCalls = [];
  api.emailsCalls = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "https://github.com/login/oauth/access_token") {
        const body = new URLSearchParams(init!.body as string);
        tokenEndpoint.calls.push(body);
        const expected = tokenEndpoint.challengeForCode.get(body.get("code") ?? "");
        const actual = createHash("sha256")
          .update(body.get("code_verifier") ?? "")
          .digest("base64url");

        if (!expected || expected !== actual) {
          return new Response(JSON.stringify({ error: "bad_verification_code" }), { status: 200 });
        }

        return new Response(JSON.stringify({ access_token: api.accessToken }), { status: 200 });
      }

      if (url === "https://api.github.com/user") {
        api.userCalls.push(new Request(url, init));
        return new Response(JSON.stringify(api.user), { status: 200 });
      }

      if (url === "https://api.github.com/user/emails") {
        api.emailsCalls.push(new Request(url, init));
        return new Response(JSON.stringify(api.emails), { status: 200 });
      }

      throw new Error(`unexpected fetch: ${url}`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("startProviderLogin (github)", () => {
  it("redirects with state and an S256 PKCE challenge, and stores them in a short-lived signed cookie", async () => {
    const { url, cookie } = await startLogin();

    expect(url.origin + url.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("read:user user:email");
    expect(cookie.options).toMatchObject({ raw: true, path: "/", maxAge: 600 });
    // GitHub's callback is a top-level GET redirect — no SameSite/Secure override, unlike Apple's form_post.
    expect(cookie.options).not.toHaveProperty("sameSite");
    expect(cookie.options).not.toHaveProperty("secure");
  });
});

describe("completeProviderLogin (github)", () => {
  it("exchanges the code with the cookie's PKCE verifier, fetches the profile, creates + links a verified user, and finishes through completeLogin", async () => {
    const login = await startLogin();

    const result = await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tokenEndpoint.calls).toHaveLength(1);
    expect(api.userCalls).toHaveLength(1);
    expect(api.userCalls[0]!.headers.get("authorization")).toBe(`Bearer ${api.accessToken}`);
    expect(api.userCalls[0]!.headers.get("user-agent")).toBe("warlock.js-auth");
    expect(tables.get("users")).toHaveLength(1);
    expect(tables.get("users")![0]).toMatchObject({ email: "ada@example.com", name: "Ada" });
    expect(tables.get("provider_accounts")![0]).toMatchObject({
      provider: "github",
      provider_user_id: "555",
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

    const error = await callback(attacker.cookie.value, {
      code: victim.code,
      state: attacker.state,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(InvalidProviderCallbackError);
    expect(error.reason).toBe("code-exchange-failed");
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("rejects a missing access_token in an otherwise-200 token response", async () => {
    const login = await startLogin();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "https://github.com/login/oauth/access_token") {
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

  it("never links or creates on an UNVERIFIED provider email — not even to an existing account with that email", async () => {
    await User.create({ email: "ada@example.com" });
    api.emails = [{ email: "ada@example.com", primary: true, verified: false }];
    const login = await startLogin();

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

    await callback(login.cookie.value, { code: login.code, state: login.state });

    expect(tables.get("users")).toHaveLength(1);
    expect(defined(tables.get("provider_accounts")?.[0], "row").user_id).toBe(existing.id);
    expect((defined(completeLogin.mock.calls[0], "first call")[0] as User).id).toBe(existing.id);
  });

  it("an existing link resolves the user by provider id, whatever the email says now", async () => {
    const linked = await User.create({ email: "old@example.com" });
    tables.set("provider_accounts", [
      {
        id: 900,
        provider: "github",
        provider_user_id: "555",
        user_id: linked.id,
        user_type: "user",
      },
    ]);
    api.emails = [];
    const login = await startLogin();

    await callback(login.cookie.value, { code: login.code, state: login.state });

    expect((defined(completeLogin.mock.calls[0], "first call")[0] as User).id).toBe(linked.id);
    expect(tables.get("users")).toHaveLength(1);
  });
});
