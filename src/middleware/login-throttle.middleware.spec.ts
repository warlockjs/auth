import { beforeEach, describe, expect, it, vi } from "vitest";

const cacheGet = vi.fn();
const cacheSet = vi.fn();
const cacheRemove = vi.fn();
const cacheUpdate = vi.fn();

vi.mock("@warlock.js/cache", () => ({
  cache: {
    get: (...args: unknown[]) => cacheGet(...args),
    set: (...args: unknown[]) => cacheSet(...args),
    remove: (...args: unknown[]) => cacheRemove(...args),
    update: (...args: unknown[]) => cacheUpdate(...args),
  },
}));

vi.mock("@warlock.js/core", () => ({
  t: (key: string) => key,
}));

vi.mock("@warlock.js/logger", () => ({
  log: { error: vi.fn() },
}));

import { loginThrottleMiddleware } from "./login-throttle.middleware";
import { AuthErrorCodes } from "../utils/auth-error-codes";

type SentCallback = (response: FakeResponse) => void | Promise<void>;

type FakeRequest = {
  input: (key: string) => unknown;
  detectIp: () => string | undefined;
};

type FakeResponse = {
  isOk: boolean;
  onSent: (callback: SentCallback) => void;
  tooManyRequests: ReturnType<typeof vi.fn>;
  fireSent: () => Promise<void>;
};

function buildRequest(body: Record<string, unknown> = {}): FakeRequest {
  const merged: Record<string, unknown> = { email: "sara@example.com", ...body };

  return {
    input: (key: string) => merged[key],
    detectIp: () => "1.2.3.4",
  };
}

function buildResponse(isOk: boolean): FakeResponse {
  const callbacks: SentCallback[] = [];

  const response: FakeResponse = {
    isOk,
    onSent: (callback) => {
      callbacks.push(callback);
    },
    tooManyRequests: vi.fn(),
    fireSent: async () => {
      for (const callback of callbacks) {
        await callback(response);
      }
    },
  };

  return response;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("loginThrottleMiddleware", () => {
  it("rejects pre-controller with 429 when an identifier is already locked", async () => {
    cacheGet.mockImplementation((key: string) =>
      key.startsWith("auth.throttle.lock.") ? true : null,
    );

    const middleware = loginThrottleMiddleware();
    const request = buildRequest();
    const response = buildResponse(true);

    await middleware(request as never, response as never);

    expect(response.tooManyRequests).toHaveBeenCalledOnce();
    expect(response.tooManyRequests).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.TooManyAttempts }),
    );
  });

  it("seeds the failure counter with a TTL on the first failure (fixed window)", async () => {
    // counter absent → loginThrottle seeds TTL on first failure
    cacheGet.mockResolvedValue(null);
    cacheUpdate.mockResolvedValue(1);

    const middleware = loginThrottleMiddleware({ max: 5, window: "10m", by: ["email"] });
    const request = buildRequest();
    const response = buildResponse(false);

    await middleware(request as never, response as never);
    await response.fireSent();

    expect(cacheUpdate).toHaveBeenCalledWith(
      "auth.throttle.count.email.sara@example.com",
      expect.any(Function),
      { ttl: "10m" },
    );
    // no lock yet — count (1) is below max (5)
    expect(cacheSet).not.toHaveBeenCalled();
  });

  it("sets the lock key once the failure counter reaches `max`", async () => {
    // counter already exists (any non-null) → TTL preserved, not re-seeded
    cacheGet.mockResolvedValue(0);
    cacheUpdate.mockResolvedValue(5);

    const middleware = loginThrottleMiddleware({
      max: 5,
      lockoutDuration: "20m",
      by: ["email"],
    });
    const request = buildRequest();
    const response = buildResponse(false);

    await middleware(request as never, response as never);
    await response.fireSent();

    expect(cacheUpdate).toHaveBeenCalledWith(
      "auth.throttle.count.email.sara@example.com",
      expect.any(Function),
      undefined, // TTL preserved across bumps — fixed window
    );
    expect(cacheSet).toHaveBeenCalledWith(
      "auth.throttle.lock.email.sara@example.com",
      true,
      { ttl: "20m" },
    );
  });

  it("clears the counter and the lock on a successful response", async () => {
    cacheGet.mockResolvedValue(null);

    const middleware = loginThrottleMiddleware({ by: ["email"] });
    const request = buildRequest();
    const response = buildResponse(true);

    await middleware(request as never, response as never);
    await response.fireSent();

    expect(cacheRemove).toHaveBeenCalledWith("auth.throttle.count.email.sara@example.com");
    expect(cacheRemove).toHaveBeenCalledWith("auth.throttle.lock.email.sara@example.com");
    expect(cacheUpdate).not.toHaveBeenCalled();
  });

  it("no-ops when no identifier can be extracted (request lacks email and ip)", async () => {
    const middleware = loginThrottleMiddleware();
    const request: FakeRequest = {
      input: () => undefined,
      detectIp: () => undefined,
    };
    const response = buildResponse(true);

    await middleware(request as never, response as never);

    expect(cacheGet).not.toHaveBeenCalled();
    expect(response.tooManyRequests).not.toHaveBeenCalled();
  });

  it("tracks every identifier independently — bumps the counter for each", async () => {
    cacheGet.mockResolvedValue(null);
    cacheUpdate.mockResolvedValue(1);

    const middleware = loginThrottleMiddleware({ by: ["email", "ip"] });
    const request = buildRequest();
    const response = buildResponse(false);

    await middleware(request as never, response as never);
    await response.fireSent();

    // both the per-account AND the per-source counter must be bumped
    expect(cacheUpdate).toHaveBeenCalledWith(
      "auth.throttle.count.email.sara@example.com",
      expect.any(Function),
      expect.any(Object),
    );
    expect(cacheUpdate).toHaveBeenCalledWith(
      "auth.throttle.count.ip.1.2.3.4",
      expect.any(Function),
      expect.any(Object),
    );
  });

  it("fails open when the cache rejects (driver outage must not escalate to an auth outage)", async () => {
    cacheGet.mockRejectedValue(new Error("CacheDriverNotInitialized"));

    const middleware = loginThrottleMiddleware();
    const request = buildRequest();
    const response = buildResponse(true);

    // must NOT throw and must NOT 429
    await expect(middleware(request as never, response as never)).resolves.toBeUndefined();
    expect(response.tooManyRequests).not.toHaveBeenCalled();
  });
});
