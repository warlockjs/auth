import { beforeEach, describe, expect, it, vi } from "vitest";

const filesExists = vi.fn();
const filesGet = vi.fn();
const filesPut = vi.fn();
const rootPath = vi.fn((file: string) => `/root/${file}`);
const environment = vi.fn(() => "development");
const randomToken = vi.fn(() => "GENERATED_SECRET");

vi.mock("@warlock.js/fs", () => ({
  fs: {
    files: {
      exists: (...args: unknown[]) => filesExists(...args),
      get: (...args: unknown[]) => filesGet(...args),
      put: (...args: unknown[]) => filesPut(...args),
    },
  },
}));

vi.mock("@warlock.js/core", () => ({
  rootPath: (...args: unknown[]) => rootPath(...args),
  environment: (...args: unknown[]) => environment(...args),
}));

vi.mock("@warlock.js/logger", () => ({
  log: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), success: vi.fn() },
}));

vi.mock("@mongez/reinforcements", () => ({
  Random: { token: (...args: unknown[]) => randomToken(...args) },
}));

import { generateJWTSecret } from "./generate-jwt-secret";

beforeEach(() => {
  vi.clearAllMocks();
  rootPath.mockImplementation((file: string) => `/root/${file}`);
  environment.mockReturnValue("development");
});

describe("generateJWTSecret", () => {
  it("does nothing (no write) when no env file can be found", async () => {
    filesExists.mockResolvedValue(false);

    await generateJWTSecret();

    expect(filesGet).not.toHaveBeenCalled();
    expect(filesPut).not.toHaveBeenCalled();
  });

  it("falls back to .env.development when .env is absent in development", async () => {
    // .env missing, .env.development present
    filesExists.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    filesGet.mockResolvedValue("");
    filesPut.mockResolvedValue(undefined);

    await generateJWTSecret();

    expect(rootPath).toHaveBeenCalledWith(".env.development");
    expect(filesGet).toHaveBeenCalledWith("/root/.env.development");
  });

  it("falls back to .env.production when .env is absent in production", async () => {
    environment.mockReturnValue("production");
    filesExists.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    filesGet.mockResolvedValue("");
    filesPut.mockResolvedValue(undefined);

    await generateJWTSecret();

    expect(rootPath).toHaveBeenCalledWith(".env.production");
  });

  it("writes both secrets when neither is present", async () => {
    filesExists.mockResolvedValue(true);
    filesGet.mockResolvedValue("APP_NAME=demo\n");
    filesPut.mockResolvedValue(undefined);

    await generateJWTSecret();

    expect(filesPut).toHaveBeenCalledTimes(1);
    const [, written] = filesPut.mock.calls[0];
    expect(written).toContain("JWT_SECRET=GENERATED_SECRET");
    expect(written).toContain("JWT_REFRESH_SECRET=GENERATED_SECRET");
    // original contents are preserved
    expect(written).toContain("APP_NAME=demo");
    // secrets must come from the crypto-backed Random.token, not Math.random()-backed Random.string
    expect(randomToken).toHaveBeenCalledTimes(2);
  });

  it("adds only the refresh secret when JWT_SECRET already exists", async () => {
    filesExists.mockResolvedValue(true);
    filesGet.mockResolvedValue("JWT_SECRET=already-here\n");
    filesPut.mockResolvedValue(undefined);

    await generateJWTSecret();

    const [, written] = filesPut.mock.calls[0];
    expect(written).toContain("JWT_REFRESH_SECRET=GENERATED_SECRET");
    // it must not append a second JWT_SECRET line
    expect(written.match(/JWT_SECRET=/g)).toHaveLength(1);
  });

  it("does not write when both secrets already exist", async () => {
    filesExists.mockResolvedValue(true);
    filesGet.mockResolvedValue("JWT_SECRET=a\nJWT_REFRESH_SECRET=b\n");

    await generateJWTSecret();

    expect(filesPut).not.toHaveBeenCalled();
  });
});
