import { DatabaseDirtyTracker, dataSourceRegistry, type DriverContract } from "@warlock.js/cascade";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from "vitest";
import { AccessToken } from "./access-token/access-token.model";
import { OneTimeToken } from "./one-time-token/one-time-token.model";
import { RefreshToken } from "./refresh-token/refresh-token.model";

/**
 * The persisted token rows carry bearer credentials (the signed JWT itself for
 * access/refresh tokens, the code hash for one-time tokens). Any
 * `response.json(model)` / resource that serializes one of these rows must not
 * leak that material — the real cascade `Model` is used here, unmocked, so the
 * assertions run against the actual `toJSON()` path.
 */
const ACCESS_TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.access-secret-payload.signature";
const REFRESH_TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.refresh-secret-payload.signature";
const ONE_TIME_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

let warnSpy: MockInstance<typeof console.warn>;

/**
 * Model construction only asks the driver for a dirty tracker, so a stub
 * driver is enough to build real, in-memory model instances — no database.
 */
beforeAll(() => {
  dataSourceRegistry.register({
    name: "token-serialization-spec",
    driver: {
      name: "stub",
      on: () => undefined,
      getDirtyTracker: (data: Record<string, unknown>) => new DatabaseDirtyTracker(data),
    } as unknown as DriverContract,
    isDefault: true,
  });
});

afterAll(() => {
  dataSourceRegistry.clear();
});

beforeEach(() => {
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  warnSpy.mockRestore();
});

function buildAccessToken() {
  return new AccessToken({
    token: ACCESS_TOKEN_VALUE,
    user_id: 7,
    user_type: "user",
    expires_at: new Date(Date.now() + 60_000),
  });
}

function buildRefreshToken() {
  return new RefreshToken({
    token: REFRESH_TOKEN_VALUE,
    user_id: 7,
    user_type: "user",
    family_id: "family-1",
    expires_at: new Date(Date.now() + 60_000),
    device_info: { userAgent: "spec-agent", ip: "127.0.0.1" },
  });
}

function buildOneTimeToken() {
  return new OneTimeToken({
    token_hash: ONE_TIME_TOKEN_HASH,
    purpose: "password-reset",
    user_id: 7,
    user_type: "user",
    expires_at: new Date(Date.now() + 60_000),
  });
}

describe("AccessToken serialization hides the bearer token", () => {
  it("toJSON() does not include the token", () => {
    const json = buildAccessToken().toJSON();

    expect(json).not.toHaveProperty("token");
    expect(JSON.stringify(json)).not.toContain(ACCESS_TOKEN_VALUE);
    expect(json).toMatchObject({ user_id: 7, user_type: "user" });
  });

  it("JSON.stringify(model) does not include the token", () => {
    expect(JSON.stringify(buildAccessToken())).not.toContain(ACCESS_TOKEN_VALUE);
  });

  it("internal reads still see the token", () => {
    const model = buildAccessToken();

    expect(model.get("token")).toBe(ACCESS_TOKEN_VALUE);
    expect(model.data.token).toBe(ACCESS_TOKEN_VALUE);
  });

  it("findByToken still queries by the raw token column", async () => {
    const first = vi.spyOn(AccessToken, "first").mockResolvedValue(null);

    await AccessToken.findByToken(ACCESS_TOKEN_VALUE);

    expect(first).toHaveBeenCalledWith({ token: ACCESS_TOKEN_VALUE });
    first.mockRestore();
  });

  it("does not trigger cascade's sensitive-field warning", () => {
    // Cascade warns once per class, so probe with a fresh subclass that
    // inherits the schema and `hidden` list but has not been checked yet.
    class AccessTokenProbe extends AccessToken {}

    new AccessTokenProbe({ token: "probe" }).toJSON();

    const warnings = warnSpy.mock.calls.map((call) => String(call[0]));

    expect(warnings.filter((message) => message.includes('"access_tokens"'))).toEqual([]);
  });
});

describe("RefreshToken serialization hides the bearer token", () => {
  it("toJSON() does not include the token", () => {
    const json = buildRefreshToken().toJSON();

    expect(json).not.toHaveProperty("token");
    expect(JSON.stringify(json)).not.toContain(REFRESH_TOKEN_VALUE);
    expect(json).toMatchObject({ user_id: 7, family_id: "family-1" });
  });

  it("JSON.stringify(model) does not include the token", () => {
    expect(JSON.stringify(buildRefreshToken())).not.toContain(REFRESH_TOKEN_VALUE);
  });

  it("internal reads still see the token", () => {
    const model = buildRefreshToken();

    expect(model.get("token")).toBe(REFRESH_TOKEN_VALUE);
    expect(model.data.token).toBe(REFRESH_TOKEN_VALUE);
  });

  it("findByToken / findForUser still query by the raw token column", async () => {
    const first = vi.spyOn(RefreshToken, "first").mockResolvedValue(null);

    await RefreshToken.findByToken(REFRESH_TOKEN_VALUE);
    await RefreshToken.findForUser({ id: 7 } as never, REFRESH_TOKEN_VALUE);

    expect(first).toHaveBeenNthCalledWith(1, { token: REFRESH_TOKEN_VALUE });
    expect(first).toHaveBeenNthCalledWith(2, { token: REFRESH_TOKEN_VALUE, user_id: 7 });
    first.mockRestore();
  });

  it("does not trigger cascade's sensitive-field warning", () => {
    // Cascade warns once per class, so probe with a fresh subclass that
    // inherits the schema and `hidden` list but has not been checked yet.
    class RefreshTokenProbe extends RefreshToken {}

    new RefreshTokenProbe({ token: "probe" }).toJSON();

    const warnings = warnSpy.mock.calls.map((call) => String(call[0]));

    expect(warnings.filter((message) => message.includes('"refresh_tokens"'))).toEqual([]);
  });
});

describe("OneTimeToken serialization hides the code hash", () => {
  it("toJSON() / JSON.stringify(model) do not include token_hash", () => {
    const model = buildOneTimeToken();

    expect(model.toJSON()).not.toHaveProperty("token_hash");
    expect(JSON.stringify(model)).not.toContain(ONE_TIME_TOKEN_HASH);
  });

  it("internal reads still see token_hash", () => {
    expect(buildOneTimeToken().get("token_hash")).toBe(ONE_TIME_TOKEN_HASH);
  });

  it("findByHash still queries by the raw token_hash column", async () => {
    const first = vi.spyOn(OneTimeToken, "first").mockResolvedValue(null);

    await OneTimeToken.findByHash(ONE_TIME_TOKEN_HASH, "password-reset");

    expect(first).toHaveBeenCalledWith({
      token_hash: ONE_TIME_TOKEN_HASH,
      purpose: "password-reset",
    });
    first.mockRestore();
  });
});
