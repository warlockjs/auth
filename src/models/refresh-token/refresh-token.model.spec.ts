import { beforeEach, describe, expect, it, vi } from "vitest";

const modelFirst = vi.fn();
const modelCreate = vi.fn();
const modelDelete = vi.fn();
const modelQuery = vi.fn();
const modelAtomic = vi.fn();

vi.mock("@warlock.js/cascade", () => ({
  Model: class {
    public static first = (...args: unknown[]) => modelFirst(...args);
    public static create = (...args: unknown[]) => modelCreate(...args);
    public static delete = (...args: unknown[]) => modelDelete(...args);
    public static query = (...args: unknown[]) => modelQuery(...args);
    public static atomic = (...args: unknown[]) => modelAtomic(...args);
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
    v: {
      object: chained,
      string: chained,
      scalar: chained,
      date: chained,
      record: chained,
      any: chained,
    },
  };
});

import { RefreshToken } from "./refresh-token.model";

function buildToken(fields: Record<string, unknown>) {
  const token = Object.create(RefreshToken.prototype) as RefreshToken;

  Object.defineProperty(token, "get", { value: (key: string) => fields[key] });
  Object.defineProperty(token, "id", { value: fields.id ?? "rt-id" });

  return token;
}

function buildMutableToken() {
  const token = Object.create(RefreshToken.prototype) as RefreshToken;

  const save = vi.fn().mockResolvedValue(token);
  const merge = vi.fn((_patch: Record<string, unknown>) => ({ save }));

  Object.defineProperty(token, "merge", { value: merge });

  return { token, merge, save };
}

function buildQueryStub(rows: unknown[]) {
  const builder: Record<string, unknown> = {};

  builder.where = vi.fn(() => builder);
  builder.orderBy = vi.fn(() => builder);
  builder.get = vi.fn().mockResolvedValue(rows);

  return builder;
}

const user = { id: 7, userType: "user" } as never;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("RefreshToken validity getters", () => {
  it("isExpired reflects expires_at relative to now", () => {
    expect(buildToken({ expires_at: new Date(Date.now() + 60_000) }).isExpired).toBe(false);
    expect(buildToken({ expires_at: new Date(Date.now() - 60_000) }).isExpired).toBe(true);
    expect(buildToken({ expires_at: undefined }).isExpired).toBe(false);
  });

  it("isRevoked reflects the presence of revoked_at", () => {
    expect(buildToken({ revoked_at: new Date() }).isRevoked).toBe(true);
    expect(buildToken({ revoked_at: undefined }).isRevoked).toBe(false);
  });

  it("isValid is true only when neither expired nor revoked", () => {
    const future = new Date(Date.now() + 60_000);

    expect(buildToken({ expires_at: future, revoked_at: undefined }).isValid).toBe(true);
    expect(buildToken({ expires_at: future, revoked_at: new Date() }).isValid).toBe(false);
    expect(buildToken({ expires_at: new Date(Date.now() - 1), revoked_at: undefined }).isValid).toBe(
      false,
    );
  });

  it("familyId reads the family_id column", () => {
    expect(buildToken({ family_id: "fam-9" }).familyId).toBe("fam-9");
  });
});

describe("RefreshToken.revoke / markAsUsed", () => {
  it("revoke merges a revoked_at and saves", async () => {
    const { token, merge, save } = buildMutableToken();

    await token.revoke();

    expect(merge.mock.calls[0][0].revoked_at).toBeInstanceOf(Date);
    expect(save).toHaveBeenCalledOnce();
  });

  it("markAsUsed merges last_used_at only and resolves to undefined", async () => {
    const { token, merge } = buildMutableToken();

    await expect(token.markAsUsed()).resolves.toBeUndefined();
    expect(merge.mock.calls[0][0].last_used_at).toBeInstanceOf(Date);
    expect(merge.mock.calls[0][0].revoked_at).toBeUndefined();
  });
});

describe("RefreshToken.revokeIfActive", () => {
  it("conditionally revokes by id + revoked_at:null and reports the winner (count > 0)", async () => {
    modelAtomic.mockResolvedValue(1);
    const token = buildToken({ id: "rt-42" });

    const won = await token.revokeIfActive();

    expect(won).toBe(true);
    expect(modelAtomic).toHaveBeenCalledWith(
      { id: "rt-42", revoked_at: null },
      { $set: { revoked_at: expect.any(Date) } },
    );
  });

  it("reports a lost race when nothing was modified (count === 0)", async () => {
    modelAtomic.mockResolvedValue(0);

    expect(await buildToken({ id: "rt-1" }).revokeIfActive()).toBe(false);
  });
});

describe("RefreshToken statics", () => {
  it("issue maps user + options to a create() call", async () => {
    await RefreshToken.issue(user, "tok", {
      familyId: "fam-1",
      expiresAt: "2030-01-01T00:00:00.000Z",
      deviceInfo: { ip: "1.2.3.4", userAgent: "ua", deviceId: "d" },
    });

    expect(modelCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        token: "tok",
        user_id: 7,
        user_type: "user",
        family_id: "fam-1",
        expires_at: "2030-01-01T00:00:00.000Z",
        device_info: { ip: "1.2.3.4", userAgent: "ua", deviceId: "d" },
      }),
    );
  });

  it("findByToken / findForUser / deleteForUser scope by the right columns", async () => {
    await RefreshToken.findByToken("tok");
    expect(modelFirst).toHaveBeenCalledWith({ token: "tok" });

    await RefreshToken.findForUser(user, "tok");
    expect(modelFirst).toHaveBeenCalledWith({ token: "tok", user_id: 7 });

    await RefreshToken.deleteForUser(user, "tok");
    expect(modelDelete).toHaveBeenCalledWith({ token: "tok", user_id: 7 });
  });

  it("revokeAllFor fetches active rows, revokes each, and returns them", async () => {
    const rows = [{ revoke: vi.fn() }, { revoke: vi.fn() }];
    const query = buildQueryStub(rows);
    modelQuery.mockReturnValue(query);

    const result = await RefreshToken.revokeAllFor(user);

    expect(query.where).toHaveBeenCalledWith({ user_id: 7, user_type: "user", revoked_at: null });
    expect(rows[0].revoke).toHaveBeenCalledOnce();
    expect(rows[1].revoke).toHaveBeenCalledOnce();
    // the revoked rows are returned so the service can emit a per-token event
    expect(result).toBe(rows);
  });

  it("revokeFamily fetches active rows in the family, revokes each, and returns them", async () => {
    const rows = [{ revoke: vi.fn() }];
    const query = buildQueryStub(rows);
    modelQuery.mockReturnValue(query);

    const result = await RefreshToken.revokeFamily("fam-9");

    expect(query.where).toHaveBeenCalledWith({ family_id: "fam-9", revoked_at: null });
    expect(rows[0].revoke).toHaveBeenCalledOnce();
    expect(result).toBe(rows);
  });

  it("activeFor queries active, unexpired rows newest-first", async () => {
    const query = buildQueryStub([]);
    modelQuery.mockReturnValue(query);

    await RefreshToken.activeFor(user);

    expect(query.where).toHaveBeenCalledWith({ user_id: 7, user_type: "user", revoked_at: null });
    expect(query.where).toHaveBeenCalledWith("expires_at", ">", expect.any(Date));
    expect(query.orderBy).toHaveBeenCalledWith("created_at", "desc");
  });

  it("enforceMax revokes only the oldest surplus tokens", async () => {
    const rows = [
      { revoke: vi.fn() },
      { revoke: vi.fn() },
      { revoke: vi.fn() },
    ];
    modelQuery.mockReturnValue(buildQueryStub(rows));

    // 3 active, max 2 → slice(0, 3 - 2 + 1) = oldest 2 revoked, newest kept
    await RefreshToken.enforceMax(user, 2);

    expect(rows[0].revoke).toHaveBeenCalledOnce();
    expect(rows[1].revoke).toHaveBeenCalledOnce();
    expect(rows[2].revoke).not.toHaveBeenCalled();
  });

  it("enforceMax revokes nothing when under the cap", async () => {
    const rows = [{ revoke: vi.fn() }];
    modelQuery.mockReturnValue(buildQueryStub(rows));

    await RefreshToken.enforceMax(user, 5);

    expect(rows[0].revoke).not.toHaveBeenCalled();
  });

  it("purgeExpired destroys each expired row and returns them", async () => {
    const rows = [{ destroy: vi.fn() }, { destroy: vi.fn() }];
    modelQuery.mockReturnValue(buildQueryStub(rows));

    const result = await RefreshToken.purgeExpired();

    expect(rows[0].destroy).toHaveBeenCalledOnce();
    expect(rows[1].destroy).toHaveBeenCalledOnce();
    expect(result).toBe(rows);
  });
});
