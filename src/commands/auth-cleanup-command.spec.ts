import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cleanupExpiredTokens = vi.fn();

// `command` from core just registers metadata; returning the config verbatim
// lets the spec invoke the real `action` and assert its branch behavior.
vi.mock("@warlock.js/core", () => ({
  command: (config: unknown) => config,
}));

// Strip the ANSI helpers down to identity so assertions match on plain text.
vi.mock("@mongez/copper", () => ({
  colors: {
    cyan: (text: string) => text,
    green: (text: string) => text,
  },
}));

vi.mock("../services/auth.service", () => ({
  authService: {
    cleanupExpiredTokens: (...args: unknown[]) => cleanupExpiredTokens(...args),
  },
}));

import { registerAuthCleanupCommand } from "./auth-cleanup-command";

let logSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
});

afterEach(() => {
  logSpy.mockRestore();
});

/** All console output produced by the command, flattened into one string. */
function loggedText(): string {
  return logSpy.mock.calls.map((call) => call.join(" ")).join("\n");
}

describe("registerAuthCleanupCommand", () => {
  it("registers under the auth.cleanup name", () => {
    const cmd = registerAuthCleanupCommand() as { name: string };

    expect(cmd.name).toBe("auth.cleanup");
  });

  it("delegates to authService.cleanupExpiredTokens and reports the removed count", async () => {
    cleanupExpiredTokens.mockResolvedValue(3);
    const cmd = registerAuthCleanupCommand() as { action: () => Promise<void> };

    await cmd.action();

    expect(cleanupExpiredTokens).toHaveBeenCalledOnce();
    expect(loggedText()).toContain("Removed 3");
  });

  it("reports the empty case when nothing was expired", async () => {
    cleanupExpiredTokens.mockResolvedValue(0);
    const cmd = registerAuthCleanupCommand() as { action: () => Promise<void> };

    await cmd.action();

    expect(loggedText()).toContain("No expired tokens");
  });
});
