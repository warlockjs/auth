import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ── in-memory cascade store ─────────────────────────────────────────────────
// Every store call yields before touching the rows, so two concurrent flows
// genuinely interleave. `atomic` then reads + writes in one synchronous step —
// the same compare-and-set guarantee a conditional UPDATE / updateMany gives.
type Row = Record<string, unknown>;

const tokenRows: Row[] = [];
let nextId = 0;

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

function matches(row: Row, filter: Row): boolean {
  return Object.entries(filter).every(([key, value]) =>
    value === null ? row[key] === null || row[key] === undefined : row[key] === value,
  );
}

vi.mock("@warlock.js/cascade", () => ({
  Model: class {
    public data: Row;

    public constructor(data: Row) {
      this.data = { ...data };
    }

    public get id() {
      return this.data.id;
    }

    public get(key: string) {
      return this.data[key];
    }

    public static async create(this: new (data: Row) => unknown, data: Row) {
      await tick();
      const row = { id: ++nextId, consumed_at: null, ...data };
      tokenRows.push(row);

      return new this(row);
    }

    public static async first(this: new (data: Row) => unknown, filter: Row) {
      await tick();
      const row = tokenRows.find((candidate) => matches(candidate, filter));

      return row ? new this(row) : null;
    }

    public static async atomic(filter: Row, operations: { $set: Row }) {
      await tick();
      let modified = 0;

      for (const row of tokenRows.filter((candidate) => matches(candidate, filter))) {
        Object.assign(row, operations.$set);
        modified++;
      }

      return modified;
    }
  },
  migrate: vi.fn(() => ({})),
}));

vi.mock("@warlock.js/seal", () => {
  const chained = () => {
    const proxy: Record<string, unknown> = {};
    for (const method of ["required", "optional", "default", "in"]) {
      proxy[method] = () => proxy;
    }

    return proxy;
  };

  return { v: { object: chained, string: chained, scalar: chained, date: chained } };
});

// ── core ────────────────────────────────────────────────────────────────────
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
    config: {
      key: (key: string, fallback?: unknown) =>
        key in configValues ? configValues[key] : fallback,
    },
    hashPassword: async (plain: string) => `hashed:${plain}`,
    verifyPassword: async (plain: string, stored: string) => stored === `hashed:${plain}`,
    t: (key: string) => key,
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

vi.mock("@warlock.js/logger", () => ({ log: { warn: vi.fn(), error: vi.fn() } }));

const revokeAllTokens = vi.fn();

vi.mock("./auth.service", () => ({
  authService: {
    revokeAllTokens: (...args: unknown[]) => revokeAllTokens(...args),
    hashPassword: async (plain: string) => `hashed:${plain}`,
    verifyPassword: async (plain: string, stored: string) => stored === `hashed:${plain}`,
  },
}));

// ── notifications ───────────────────────────────────────────────────────────
const notificationState = { configured: true };
const definitions: Array<{ type: string; via: string[]; send: ReturnType<typeof vi.fn> }> = [];

vi.mock("@warlock.js/notifications", () => {
  return {
    getNotificationConfig: () => {
      if (!notificationState.configured) {
        throw new Error("Notifications not configured");
      }

      return { channels: { mail: {} } };
    },
    defineNotification: (definition: { type: string; via: string[] }) => {
      const notification = { ...definition, send: vi.fn() };
      definitions.push(notification);

      return notification;
    },
  };
});

// ── fake user model ─────────────────────────────────────────────────────────
type FakeUser = {
  id: number;
  userType: string;
  data: Row;
  get: (key: string) => unknown;
  string: (key: string) => string | undefined;
  merge: (values: Row) => FakeUser;
  save: () => Promise<FakeUser>;
};

const users = new Map<number, FakeUser>();

/** `hashOnSave` mimics core's `useHashedPassword()` transformer. */
function makeUser(id: number, data: Row, options: { hashOnSave?: boolean; strip?: string[] } = {}) {
  const dirty = new Set<string>();
  const user: FakeUser = {
    id,
    userType: "user",
    data: { ...data },
    get: (key) => user.data[key],
    string: (key) => user.data[key] as string | undefined,
    merge: (values) => {
      Object.assign(user.data, values);
      Object.keys(values).forEach((key) => dirty.add(key));

      return user;
    },
    save: async () => {
      if (options.hashOnSave && dirty.has("password")) {
        user.data.password = `hashed:${user.data.password}`;
      }

      for (const key of options.strip ?? []) {
        delete user.data[key];
      }

      dirty.clear();

      return user;
    },
  };

  users.set(id, user);

  return user;
}

const UserModel = {
  find: async (id: number) => users.get(id) ?? null,
  first: async (filter: Row) =>
    [...users.values()].find((user) => matches(user.data, filter)) ?? null,
};

import { InvalidOneTimeTokenError, NotificationsUnavailableError } from "../errors";
import { OneTimeToken } from "../models/one-time-token";
import { requestPasswordReset, resetPassword } from "./password-reset";
import { isEmailVerified, sendEmailVerification, verifyEmail } from "./email-verification";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

function lastSent(type: string) {
  const definition = definitions.find((candidate) => candidate.type === type);
  const calls = definition?.send.mock.calls ?? [];

  return calls[calls.length - 1] as [FakeUser, { token: string; expiresAt: Date; url?: string }];
}

beforeEach(() => {
  tokenRows.length = 0;
  users.clear();
  definitions.forEach((definition) => definition.send.mockClear());
  revokeAllTokens.mockReset();
  notificationState.configured = true;

  for (const key of Object.keys(configValues)) delete configValues[key];

  configValues["auth.userType.user"] = UserModel;
});

describe("notifications availability", () => {
  it("throws NotificationsUnavailableError when notifications is not configured", async () => {
    notificationState.configured = false;
    const user = makeUser(1, { email: "a@x.io" });

    await expect(sendEmailVerification(user as never)).rejects.toBeInstanceOf(
      NotificationsUnavailableError,
    );
    expect(tokenRows).toHaveLength(0);
  });

  it("reset request fails the same way for a known and an unknown email when unconfigured", async () => {
    notificationState.configured = false;
    makeUser(1, { email: "known@x.io" });

    await expect(requestPasswordReset(UserModel as never, "known@x.io")).rejects.toBeInstanceOf(
      NotificationsUnavailableError,
    );
    await expect(requestPasswordReset(UserModel as never, "ghost@x.io")).rejects.toBeInstanceOf(
      NotificationsUnavailableError,
    );
  });
});

describe("email verification", () => {
  it("stores only the SHA-256 hash of a 32-byte url-safe token and mails the raw token", async () => {
    const user = makeUser(1, { email: "a@x.io" });

    await sendEmailVerification(user as never);

    const [recipient, data] = lastSent("auth.email-verification");
    expect(recipient).toBe(user);
    expect(data.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(tokenRows).toHaveLength(1);
    expect(tokenRows[0].token_hash).toBe(sha256(data.token));
    expect(JSON.stringify(tokenRows[0])).not.toContain(data.token);
    expect(tokenRows[0].purpose).toBe("email-verification");
  });

  it("defaults to a 24h expiry and honours auth.verification.expiresIn", async () => {
    const user = makeUser(1, { email: "a@x.io" });
    await sendEmailVerification(user as never);
    const ttl = (tokenRows[0].expires_at as Date).getTime() - Date.now();
    expect(ttl).toBeGreaterThan(24 * 3600_000 - 5_000);
    expect(ttl).toBeLessThanOrEqual(24 * 3600_000);

    configValues["auth.verification.expiresIn"] = "2h";
    await sendEmailVerification(user as never);
    const ttl2 = (tokenRows[1].expires_at as Date).getTime() - Date.now();
    expect(ttl2).toBeLessThanOrEqual(2 * 3600_000);
    expect(ttl2).toBeGreaterThan(2 * 3600_000 - 5_000);
  });

  it("marks the user verified via emailVerifiedAt and consumes the token", async () => {
    const user = makeUser(1, { email: "a@x.io" });
    await sendEmailVerification(user as never);
    const [, { token }] = lastSent("auth.email-verification");

    expect(isEmailVerified(user as never)).toBe(false);
    const verified = await verifyEmail(token);

    expect(verified).toBe(user);
    expect(user.data.emailVerifiedAt).toBeInstanceOf(Date);
    expect(isEmailVerified(user as never)).toBe(true);
    expect(tokenRows[0].consumed_at).toBeInstanceOf(Date);
  });

  it("rejects a second use of the same token", async () => {
    const user = makeUser(1, { email: "a@x.io" });
    await sendEmailVerification(user as never);
    const [, { token }] = lastSent("auth.email-verification");

    await verifyEmail(token);
    await expect(verifyEmail(token)).rejects.toBeInstanceOf(InvalidOneTimeTokenError);
  });

  it("lets exactly one of two concurrent consumptions succeed", async () => {
    const user = makeUser(1, { email: "a@x.io" });
    await sendEmailVerification(user as never);
    const [, { token }] = lastSent("auth.email-verification");

    const results = await Promise.allSettled([verifyEmail(token), verifyEmail(token)]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.filter((result) => result.status === "rejected");
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(InvalidOneTimeTokenError);
  });

  it("rejects an expired token", async () => {
    const user = makeUser(1, { email: "a@x.io" });
    await sendEmailVerification(user as never);
    const [, { token }] = lastSent("auth.email-verification");
    tokenRows[0].expires_at = new Date(Date.now() - 1_000);

    await expect(verifyEmail(token)).rejects.toBeInstanceOf(InvalidOneTimeTokenError);
    expect(user.data.emailVerifiedAt).toBeUndefined();
  });

  it("rejects an unknown token", async () => {
    await expect(verifyEmail("nope")).rejects.toBeInstanceOf(InvalidOneTimeTokenError);
  });

  it("fails loudly when the user schema strips the verified field", async () => {
    const user = makeUser(1, { email: "a@x.io" }, { strip: ["emailVerifiedAt"] });
    await sendEmailVerification(user as never);
    const [, { token }] = lastSent("auth.email-verification");

    await expect(verifyEmail(token)).rejects.toThrow(/emailVerifiedAt/);
  });

  it("uses an app notification from auth.verification.notification instead of the default", async () => {
    const custom = { send: vi.fn() };
    configValues["auth.verification.notification"] = custom;
    configValues["auth.verification.url"] = (token: string) => `https://app.test/verify?t=${token}`;
    const user = makeUser(1, { email: "a@x.io" });

    await sendEmailVerification(user as never);

    expect(custom.send).toHaveBeenCalledOnce();
    const data = custom.send.mock.calls[0][1];
    expect(data.url).toBe(`https://app.test/verify?t=${data.token}`);
  });
});

describe("purpose binding", () => {
  it("a verification token cannot reset a password", async () => {
    const user = makeUser(1, { email: "a@x.io", password: "hashed:old" });
    await sendEmailVerification(user as never);
    const [, { token }] = lastSent("auth.email-verification");

    await expect(resetPassword(token, "new-secret")).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
    expect(user.data.password).toBe("hashed:old");
    expect(tokenRows[0].consumed_at).toBeNull();
  });

  it("a reset token cannot verify an email", async () => {
    const user = makeUser(1, { email: "a@x.io" });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token }] = lastSent("auth.password-reset");

    await expect(verifyEmail(token)).rejects.toBeInstanceOf(InvalidOneTimeTokenError);
    expect(user.data.emailVerifiedAt).toBeUndefined();
  });
});

describe("password reset", () => {
  it("defaults to a 60 minute expiry", async () => {
    makeUser(1, { email: "a@x.io" });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const ttl = (tokenRows[0].expires_at as Date).getTime() - Date.now();

    expect(ttl).toBeLessThanOrEqual(3600_000);
    expect(ttl).toBeGreaterThan(3600_000 - 5_000);
    expect(tokenRows[0].token_hash).toBe(sha256(lastSent("auth.password-reset")[1].token));
  });

  it("returns the same result for an unknown email and sends nothing", async () => {
    makeUser(1, { email: "a@x.io" });

    const known = await requestPasswordReset(UserModel as never, "a@x.io");
    const unknown = await requestPasswordReset(UserModel as never, "ghost@x.io");

    expect(unknown).toEqual(known);
    const definition = definitions.find((candidate) => candidate.type === "auth.password-reset");
    expect(definition?.send).toHaveBeenCalledOnce();
    expect(tokenRows).toHaveLength(1);
  });

  it("issuing a new reset token invalidates the previous unused one", async () => {
    makeUser(1, { email: "a@x.io", password: "hashed:old" });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token: first }] = lastSent("auth.password-reset");
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token: second }] = lastSent("auth.password-reset");

    await expect(resetPassword(first, "new-secret")).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
    await expect(resetPassword(second, "new-secret")).resolves.toBeDefined();
  });

  it("does not invalidate another user's reset token or verification tokens", async () => {
    const a = makeUser(1, { email: "a@x.io" });
    makeUser(2, { email: "b@x.io" });
    await sendEmailVerification(a as never);
    const [, { token: verification }] = lastSent("auth.email-verification");
    await requestPasswordReset(UserModel as never, "b@x.io");
    const [, { token: otherReset }] = lastSent("auth.password-reset");

    await requestPasswordReset(UserModel as never, "a@x.io");

    await expect(verifyEmail(verification)).resolves.toBe(a);
    await expect(resetPassword(otherReset, "x-secret")).resolves.toBeDefined();
  });

  it("sets the hashed password, consumes the token and revokes every token", async () => {
    const user = makeUser(1, { email: "a@x.io", password: "hashed:old" });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token }] = lastSent("auth.password-reset");

    const result = await resetPassword(token, "new-secret");

    expect(result).toBe(user);
    expect(user.data.password).toBe("hashed:new-secret");
    expect(revokeAllTokens).toHaveBeenCalledWith(user);
    await expect(resetPassword(token, "again")).rejects.toBeInstanceOf(InvalidOneTimeTokenError);
    expect(revokeAllTokens).toHaveBeenCalledOnce();
  });

  it("does not double-hash for a model that hashes on save", async () => {
    const user = makeUser(1, { email: "a@x.io", password: "hashed:old" }, { hashOnSave: true });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token }] = lastSent("auth.password-reset");

    await resetPassword(token, "new-secret");

    expect(user.data.password).toBe("hashed:new-secret");
  });

  it("uses auth.passwordReset.setPassword when configured", async () => {
    const setPassword = vi.fn();
    configValues["auth.passwordReset.setPassword"] = setPassword;
    const user = makeUser(1, { email: "a@x.io", password: "hashed:old" });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token }] = lastSent("auth.password-reset");

    await resetPassword(token, "new-secret");

    expect(setPassword).toHaveBeenCalledWith(user, "new-secret");
    expect(user.data.password).toBe("hashed:old");
  });

  it("rejects an expired reset token without touching the password or sessions", async () => {
    const user = makeUser(1, { email: "a@x.io", password: "hashed:old" });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token }] = lastSent("auth.password-reset");
    tokenRows[0].expires_at = new Date(Date.now() - 1);

    await expect(resetPassword(token, "new-secret")).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
    expect(user.data.password).toBe("hashed:old");
    expect(revokeAllTokens).not.toHaveBeenCalled();
  });

  it("two concurrent resets with one token: exactly one wins", async () => {
    makeUser(1, { email: "a@x.io", password: "hashed:old" });
    await requestPasswordReset(UserModel as never, "a@x.io");
    const [, { token }] = lastSent("auth.password-reset");

    const results = await Promise.allSettled([
      resetPassword(token, "first-secret"),
      resetPassword(token, "second-secret"),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(revokeAllTokens).toHaveBeenCalledOnce();
  });

  it("exposes the model's table name", () => {
    expect(OneTimeToken.table).toBe("one_time_tokens");
  });
});
