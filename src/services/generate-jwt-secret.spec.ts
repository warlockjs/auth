import { beforeEach, describe, expect, it, vi } from "vitest";

const fileExistsAsync = vi.fn();
const getFileAsync = vi.fn();
const putFileAsync = vi.fn();
const rootPath = vi.fn((file: string) => `/root/${file}`);
const environment = vi.fn(() => "development");
const randomToken = vi.fn(() => "GENERATED_SECRET");

vi.mock("@warlock.js/fs", () => ({
  fileExistsAsync: (...args: unknown[]) => fileExistsAsync(...args),
  getFileAsync: (...args: unknown[]) => getFileAsync(...args),
  putFileAsync: (...args: unknown[]) => putFileAsync(...args),
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
    fileExistsAsync.mockResolvedValue(false);

    await generateJWTSecret();

    expect(getFileAsync).not.toHaveBeenCalled();
    expect(putFileAsync).not.toHaveBeenCalled();
  });

  it("falls back to .env.development when .env is absent in development", async () => {
    // .env missing, .env.development present
    fileExistsAsync.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    getFileAsync.mockResolvedValue("");
    putFileAsync.mockResolvedValue(undefined);

    await generateJWTSecret();

    expect(rootPath).toHaveBeenCalledWith(".env.development");
    expect(getFileAsync).toHaveBeenCalledWith("/root/.env.development");
  });

  it("falls back to .env.production when .env is absent in production", async () => {
    environment.mockReturnValue("production");
    fileExistsAsync.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    getFileAsync.mockResolvedValue("");
    putFileAsync.mockResolvedValue(undefined);

    await generateJWTSecret();

    expect(rootPath).toHaveBeenCalledWith(".env.production");
  });

  it("writes both secrets when neither is present", async () => {
    fileExistsAsync.mockResolvedValue(true);
    getFileAsync.mockResolvedValue("APP_NAME=demo\n");
    putFileAsync.mockResolvedValue(undefined);

    await generateJWTSecret();

    expect(putFileAsync).toHaveBeenCalledTimes(1);
    const [, written] = putFileAsync.mock.calls[0];
    expect(written).toContain("JWT_SECRET=GENERATED_SECRET");
    expect(written).toContain("JWT_REFRESH_SECRET=GENERATED_SECRET");
    // original contents are preserved
    expect(written).toContain("APP_NAME=demo");
    // secrets must come from the crypto-backed Random.token, not Math.random()-backed Random.string
    expect(randomToken).toHaveBeenCalledTimes(2);
  });

  it("adds only the refresh secret when JWT_SECRET already exists", async () => {
    fileExistsAsync.mockResolvedValue(true);
    getFileAsync.mockResolvedValue("JWT_SECRET=already-here\n");
    putFileAsync.mockResolvedValue(undefined);

    await generateJWTSecret();

    const [, written] = putFileAsync.mock.calls[0];
    expect(written).toContain("JWT_REFRESH_SECRET=GENERATED_SECRET");
    // it must not append a second JWT_SECRET line
    expect(written.match(/JWT_SECRET=/g)).toHaveLength(1);
  });

  it("does not write when both secrets already exist", async () => {
    fileExistsAsync.mockResolvedValue(true);
    getFileAsync.mockResolvedValue("JWT_SECRET=a\nJWT_REFRESH_SECRET=b\n");

    await generateJWTSecret();

    expect(putFileAsync).not.toHaveBeenCalled();
  });
});
