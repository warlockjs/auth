import { beforeEach, describe, expect, it, vi } from "vitest";

const cacheGet = vi.fn();
const cacheSet = vi.fn();
const cacheRemove = vi.fn();
const cacheIncrement = vi.fn();

vi.mock("@warlock.js/cache", () => ({
  cache: {
    get: (...args: unknown[]) => cacheGet(...args),
    set: (...args: unknown[]) => cacheSet(...args),
    remove: (...args: unknown[]) => cacheRemove(...args),
    increment: (...args: unknown[]) => cacheIncrement(...args),
  },
}));

const configValues: Record<string, unknown> = {};

vi.mock("@warlock.js/core", () => {
  class HttpError extends Error {
    public constructor(
      public status: number,
      message: string,
      public payload?: unknown,
    ) {
      super(message);
    }
  }

  return {
    t: (key: string) => key,
    config: {
      key: (key: string, fallback?: unknown) =>
        key in configValues ? configValues[key] : fallback,
    },
    HttpError,
    BadRequestError: class extends HttpError {
      public constructor(message: string, payload?: unknown) {
        super(400, message, payload);
      }
    },
    ForbiddenError: class extends HttpError {
      public constructor(message: string, payload?: unknown) {
        super(403, message, payload);
      }
    },
    ServerError: class extends HttpError {
      public constructor(message: string, payload?: unknown) {
        super(500, message, payload);
      }
    },
  };
});

vi.mock("@warlock.js/logger", () => ({ log: { error: vi.fn(), warn: vi.fn() } }));

import { EmailNotVerifiedError } from "../errors";
import { AuthErrorCodes } from "../utils/auth-error-codes";
import { requireVerifiedEmail } from "./require-verified-email.middleware";
import {
  tokenConsumeThrottleMiddleware,
  tokenIssueThrottleMiddleware,
} from "./one-time-token-throttle.middleware";
import { makeCtx } from "./test-support/make-ctx";

type SentCallback = (response: FakeResponse) => void | Promise<void>;

type FakeResponse = {
  isOk: boolean;
  onSent: (callback: SentCallback) => void;
  tooManyRequests: ReturnType<typeof vi.fn>;
  fireSent: () => Promise<void>;
};

function buildResponse(isOk: boolean): FakeResponse {
  const callbacks: SentCallback[] = [];
  const response: FakeResponse = {
    isOk,
    onSent: (callback) => {
      callbacks.push(callback);
    },
    tooManyRequests: vi.fn(),
    fireSent: async () => {
      for (const callback of callbacks) await callback(response);
    },
  };

  return response;
}

const request = {
  input: (key: string) => (key === "email" ? "Sara@x.io" : undefined),
  detectIp: () => "1.2.3.4",
};

beforeEach(() => {
  vi.clearAllMocks();
  for (const key of Object.keys(configValues)) delete configValues[key];
  cacheGet.mockResolvedValue(null);
  cacheIncrement.mockResolvedValue(1);
});

describe("tokenIssueThrottleMiddleware", () => {
  it("counts a SUCCESSFUL issue request per email and per ip (the 200 is the anti-enumeration answer)", async () => {
    const response = buildResponse(true);

    await tokenIssueThrottleMiddleware()(makeCtx({ request, response }));
    await response.fireSent();

    expect(cacheSet).toHaveBeenCalledWith("auth.throttle.count.email.sara@x.io", 0, {
      ttl: "1h",
      onConflict: "create",
    });
    expect(cacheSet).toHaveBeenCalledWith("auth.throttle.count.ip.1.2.3.4", 0, {
      ttl: "1h",
      onConflict: "create",
    });
    expect(cacheIncrement).toHaveBeenCalledWith("auth.throttle.count.email.sara@x.io");
    expect(cacheIncrement).toHaveBeenCalledWith("auth.throttle.count.ip.1.2.3.4");
    expect(cacheRemove).not.toHaveBeenCalled();
  });

  it("locks after 3 issue requests by default and rejects with 429", async () => {
    cacheIncrement.mockResolvedValue(3);
    const response = buildResponse(true);

    await tokenIssueThrottleMiddleware()(makeCtx({ request, response }));
    await response.fireSent();

    expect(cacheSet).toHaveBeenCalledWith("auth.throttle.lock.email.sara@x.io", true, {
      ttl: "1h",
    });

    cacheGet.mockImplementation(
      async (key: string) => key.startsWith("auth.throttle.lock.") || null,
    );
    const locked = buildResponse(true);
    await tokenIssueThrottleMiddleware()(makeCtx({ request, response: locked }));

    expect(locked.tooManyRequests).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.TooManyAttempts }),
    );
  });
});

describe("tokenConsumeThrottleMiddleware", () => {
  it("tracks per ip, counts failures only and clears on success", async () => {
    const failed = buildResponse(false);
    await tokenConsumeThrottleMiddleware()(makeCtx({ request, response: failed }));
    await failed.fireSent();

    expect(cacheSet).toHaveBeenCalledWith("auth.throttle.count.ip.1.2.3.4", 0, {
      ttl: "15m",
      onConflict: "create",
    });
    expect(cacheIncrement).toHaveBeenCalledWith("auth.throttle.count.ip.1.2.3.4");

    const ok = buildResponse(true);
    await tokenConsumeThrottleMiddleware()(makeCtx({ request, response: ok }));
    await ok.fireSent();

    expect(cacheRemove).toHaveBeenCalledWith("auth.throttle.count.ip.1.2.3.4");
  });
});

describe("requireVerifiedEmail", () => {
  it("throws a 403 EmailNotVerifiedError for an unverified user", async () => {
    const user = { get: () => undefined };
    const ctx = makeCtx({ request: { locals: { user } }, response: {} });

    const error = await Promise.resolve(requireVerifiedEmail()(ctx)).catch((caught) => caught);

    expect(error).toBeInstanceOf(EmailNotVerifiedError);
    expect(error.status).toBe(403);
    expect(error.payload).toEqual({ errorCode: AuthErrorCodes.EmailNotVerified });
  });

  it("passes a verified user through", async () => {
    const user = { get: (key: string) => (key === "emailVerifiedAt" ? new Date() : undefined) };

    await expect(
      Promise.resolve(
        requireVerifiedEmail()(makeCtx({ request: { locals: { user } }, response: {} })),
      ),
    ).resolves.toBeUndefined();
  });

  it("honours auth.verification.field", async () => {
    configValues["auth.verification.field"] = "verified_at";
    const user = { get: (key: string) => (key === "verified_at" ? new Date() : undefined) };

    await expect(
      Promise.resolve(
        requireVerifiedEmail()(makeCtx({ request: { locals: { user } }, response: {} })),
      ),
    ).resolves.toBeUndefined();
  });
});
