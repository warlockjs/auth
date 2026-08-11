import { createSigner } from "fast-jwt";
import { beforeEach, describe, expect, it, vi } from "vitest";

const modelFirst = vi.fn();
const modelCreate = vi.fn();
const modelDelete = vi.fn();
const modelQuery = vi.fn();

vi.mock("@warlock.js/cascade", () => ({
  Model: class {
    public static first = (...args: unknown[]) => modelFirst(...args);
    public static create = (...args: unknown[]) => modelCreate(...args);
    public static delete = (...args: unknown[]) => modelDelete(...args);
    public static query = (...args: unknown[]) => modelQuery(...args);
  },
}));

vi.mock("@warlock.js/seal", () => {
  const chained = () => {
    const proxy: Record<string, unknown> = {};
    const handler = () => proxy;

    for (const method of ["required", "optional", "default", "defaultNow"]) {
      proxy[method] = handler;
    }

    return proxy;
  };

  return {
    v: { object: chained, string: chained, scalar: chained, date: chained },
  };
});

import { AccessToken } from "./access-token.model";

function buildToken(fields: Record<string, unknown>) {
  const token = Object.create(AccessToken.prototype) as AccessToken;

  Object.defineProperty(token, "get", { value: (key: string) => fields[key] });

  return token;
}

function buildQueryStub(rows: unknown[]) {
  const builder: Record<string, unknown> = {};

  builder.where = vi.fn(() => builder);
  builder.get = vi.fn().mockResolvedValue(rows);

  return builder;
}

const user = { id: 7, userType: "admin" } as never;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("AccessToken getters", () => {
  it("expose user_id and user_type", () => {
    const token = buildToken({ user_id: 42, user_type: "admin" });

    expect(token.userId).toBe(42);
    expect(token.userType).toBe("admin");
  });
});

describe("AccessToken statics", () => {
  it("issue persists token + user + expiry", async () => {
    const expiresAt = new Date("2030-01-01T00:00:00.000Z");

    await AccessToken.issue(user, "tok", expiresAt);

    expect(modelCreate).toHaveBeenCalledWith({
      token: "tok",
      user_id: 7,
      user_type: "admin",
      expires_at: expiresAt,
    });
  });

  it("findByToken looks up by the raw token", async () => {
    await AccessToken.findByToken("tok");

    expect(modelFirst).toHaveBeenCalledWith({ token: "tok" });
  });

  it("deleteForUser scopes the delete to the user + token", async () => {
    await AccessToken.deleteForUser(user, "tok");

    expect(modelDelete).toHaveBeenCalledWith({ token: "tok", user_id: 7 });
  });

  it("deleteAllForUser deletes every token for the user", async () => {
    await AccessToken.deleteAllForUser(user);

    expect(modelDelete).toHaveBeenCalledWith({ user_id: 7 });
  });

  it("purgeExpired destroys each expired row and returns the count", async () => {
    const rows = [{ destroy: vi.fn() }, { destroy: vi.fn() }, { destroy: vi.fn() }];
    modelQuery.mockReturnValue(buildQueryStub(rows));

    const count = await AccessToken.purgeExpired();

    expect(count).toBe(3);
    expect(rows[0].destroy).toHaveBeenCalledOnce();
  });
});

/**
 * A signed token with a real `exp`, and one with none — the second is what a
 * pre-4.12.0 unparseable `expiresIn` handed to the signer.
 */
const TOKEN_WITH_EXP = createSigner({ key: "spec-secret-0123456789", expiresIn: 3_600_000 })({
  id: 1,
}) as unknown as string;
const TOKEN_WITHOUT_EXP = createSigner({ key: "spec-secret-0123456789" })({
  id: 1,
}) as unknown as string;

describe("AccessToken expiry (#27)", () => {
  it("is not expired while the persisted expiry is in the future", () => {
    const token = buildToken({ expires_at: new Date(Date.now() + 60_000) });

    expect(token.isExpired).toBe(false);
  });

  it("is expired once the persisted expiry has passed", () => {
    const token = buildToken({ expires_at: new Date(Date.now() - 60_000) });

    expect(token.isExpired).toBe(true);
  });

  // The case the whole issue turns on. `new Date() > Invalid Date` is `false`,
  // so the obvious implementation calls this row *live* — forever.
  it("treats an Invalid Date expiry as expired, not as immortal", () => {
    const token = buildToken({ expires_at: new Date("30dayz") });

    expect(token.isExpired).toBe(true);
  });

  it("treats a missing expiry as expired", () => {
    expect(buildToken({}).isExpired).toBe(true);
    expect(buildToken({ expires_at: null }).isExpired).toBe(true);
    expect(buildToken({ expires_at: "" }).isExpired).toBe(true);
  });

  it("accepts an ISO string expiry as well as a Date", () => {
    const future = buildToken({ expires_at: new Date(Date.now() + 60_000).toISOString() });
    const past = buildToken({ expires_at: new Date(Date.now() - 60_000).toISOString() });

    expect(future.isExpired).toBe(false);
    expect(past.isExpired).toBe(true);
  });

  it("flags a row with an unusable expires_at as never-expiring", () => {
    const token = buildToken({ token: TOKEN_WITH_EXP, expires_at: new Date("30dayz") });

    expect(token.neverExpires).toBe(true);
  });

  it("flags a row whose token carries no exp claim as never-expiring, even with a sane expires_at", () => {
    const token = buildToken({
      token: TOKEN_WITHOUT_EXP,
      expires_at: new Date(Date.now() + 60_000),
    });

    expect(token.neverExpires).toBe(true);
  });

  it("leaves a healthy row alone", () => {
    const token = buildToken({
      token: TOKEN_WITH_EXP,
      expires_at: new Date(Date.now() + 60_000),
    });

    expect(token.neverExpires).toBe(false);
  });
});

describe("AccessToken.findNeverExpiring / purgeNeverExpiring (#27 remediation)", () => {
  /** Rows as the store would hand them back, with a working `get`. */
  function row(fields: Record<string, unknown>) {
    const instance = buildToken(fields) as AccessToken & { destroy: ReturnType<typeof vi.fn> };

    Object.defineProperty(instance, "destroy", { value: vi.fn(), writable: true });

    return instance;
  }

  it("finds the Invalid Date row that purgeExpired provably cannot", async () => {
    const healthy = row({ token: TOKEN_WITH_EXP, expires_at: new Date(Date.now() + 60_000) });
    const poisoned = row({ token: TOKEN_WITHOUT_EXP, expires_at: new Date("30dayz") });

    modelQuery.mockReturnValue(buildQueryStub([healthy, poisoned]));

    const found = await AccessToken.findNeverExpiring();

    expect(found).toEqual([poisoned]);
  });

  it("purges the poisoned row and leaves the healthy one", async () => {
    const healthy = row({ token: TOKEN_WITH_EXP, expires_at: new Date(Date.now() + 60_000) });
    const poisoned = row({ token: TOKEN_WITHOUT_EXP, expires_at: new Date("30dayz") });

    modelQuery.mockReturnValue(buildQueryStub([healthy, poisoned]));

    const purged = await AccessToken.purgeNeverExpiring();

    expect(purged).toHaveLength(1);
    expect(poisoned.destroy).toHaveBeenCalledOnce();
    expect(healthy.destroy).not.toHaveBeenCalled();
  });

  it("removes nothing when every row is healthy", async () => {
    const healthy = row({ token: TOKEN_WITH_EXP, expires_at: new Date(Date.now() + 60_000) });

    modelQuery.mockReturnValue(buildQueryStub([healthy]));

    expect(await AccessToken.purgeNeverExpiring()).toEqual([]);
    expect(healthy.destroy).not.toHaveBeenCalled();
  });
});
