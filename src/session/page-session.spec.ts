import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const resolveRequestUser = vi.fn();
const verdict = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
  t: (key: string) => key,
  resolveCsrfOriginVerdict: (...args: unknown[]) => verdict(...args),
}));
vi.mock("@warlock.js/logger", () => ({ log: { error: vi.fn() } }));
vi.mock("../services/resolve-request-user", () => ({
  resolveRequestUser: (...args: unknown[]) => resolveRequestUser(...args),
}));

import { pageSession, sessionMiddleware } from "./page-session";

const model = { id: 7 };

function buildRequest(
  cookies: Record<string, string> = {},
  authorizationValue = "",
  method = "GET",
) {
  return {
    method,
    authorizationValue,
    cookie: (name: string) => cookies[name],
    locals: {} as Record<string, unknown>,
  } as never;
}

beforeEach(() => {
  vi.clearAllMocks();
  verdict.mockReturnValue({ allowed: true });
  configKey.mockImplementation((key: string, fallback?: unknown) =>
    key === "auth.defaultUserType" ? "user" : fallback,
  );
});

describe("pageSession", () => {
  it("throws at construction without project", () => {
    expect(() => pageSession({} as never)).toThrow(/project/);
  });

  it("returns null for a guest without touching the resolver", async () => {
    const session = pageSession({ project: (m: typeof model) => ({ id: m.id }) });

    expect(await session.resolve(buildRequest(), {} as never)).toBeNull();
    expect(resolveRequestUser).not.toHaveBeenCalled();
  });

  it("resolves a cookie with default names, renewal, user type and 30d maxAge", async () => {
    resolveRequestUser.mockResolvedValue(model);
    const session = pageSession({ project: (m: typeof model) => ({ id: m.id }) });
    const request = buildRequest({ access_token: "a" });

    expect(await session.resolve(request, {} as never)).toEqual({ model, user: { id: 7 } });
    expect(resolveRequestUser).toHaveBeenCalledWith(
      request,
      {},
      expect.objectContaining({
        tokenFrom: "cookie:access_token",
        refreshCredential: "cookie:refresh_token",
        renewalUserType: "user",
        allowedTypes: ["user"],
        maxAgeMs: 30 * 86_400_000,
      }),
    );
  });

  it("lets a present header win, with no renewal and no cookie fallback", async () => {
    resolveRequestUser.mockResolvedValue(null);
    const session = pageSession({ project: (m: typeof model) => m });
    const request = buildRequest({ access_token: "a" }, "Bearer x");

    expect(await session.resolve(request, {} as never)).toBeNull();
    expect(resolveRequestUser).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ tokenFrom: "header", refreshCredential: undefined }),
    );
  });

  it("projects once per request", async () => {
    resolveRequestUser.mockResolvedValue(model);
    const project = vi.fn((m: typeof model) => ({ id: m.id }));
    const session = pageSession({ project });
    const request = buildRequest({ access_token: "a" });

    await session.resolve(request, {} as never);
    await session.resolve(request, {} as never);

    expect(project).toHaveBeenCalledTimes(1);
  });

  it("honours a custom maxAge", async () => {
    resolveRequestUser.mockResolvedValue(model);
    const session = pageSession({ project: (m: typeof model) => m, maxAge: "1d" });

    await session.resolve(buildRequest({ access_token: "a" }), {} as never);

    expect(resolveRequestUser.mock.calls[0][2].maxAgeMs).toBe(86_400_000);
  });
});

describe("sessionMiddleware", () => {
  const response = () => ({ unauthorized: vi.fn(() => "401"), forbidden: vi.fn(() => "403") });

  it("sets the user for a signed-in cookie request", async () => {
    resolveRequestUser.mockResolvedValue(model);
    const request = buildRequest({ access_token: "a" });

    const result = await sessionMiddleware()({ request, response: response() } as never);

    expect(result).toBeUndefined();
    expect((request as any).locals.user).toBe(model);
  });

  it("rejects a guest with 401 unless optional", async () => {
    const res = response();

    expect(await sessionMiddleware()({ request: buildRequest(), response: res } as never)).toBe(
      "401",
    );
    expect(
      await sessionMiddleware({ optional: true })({
        request: buildRequest(),
        response: res,
      } as never),
    ).toBeUndefined();
  });

  it("403s a cookie POST from a foreign origin", async () => {
    verdict.mockReturnValue({ allowed: false, reason: "origin-mismatch" });

    const result = await sessionMiddleware()({
      request: buildRequest({ access_token: "a" }, "", "POST"),
      response: response(),
    } as never);

    expect(result).toBe("403");
    expect(resolveRequestUser).not.toHaveBeenCalled();
  });
});
