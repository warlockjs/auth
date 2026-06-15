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
