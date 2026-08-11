import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const findNeverExpiringTokens = vi.fn();
const purgeNeverExpiringTokens = vi.fn();

vi.mock("@warlock.js/core", () => ({
  command: (config: unknown) => config,
}));

vi.mock("@mongez/copper", () => ({
  colors: {
    cyan: (text: string) => text,
    green: (text: string) => text,
    yellow: (text: string) => text,
  },
}));

vi.mock("../services/auth.service", () => ({
  authService: {
    findNeverExpiringTokens: (...args: unknown[]) => findNeverExpiringTokens(...args),
    purgeNeverExpiringTokens: (...args: unknown[]) => purgeNeverExpiringTokens(...args),
  },
}));

import { registerAuthPurgeNeverExpiringCommand } from "./auth-purge-never-expiring-command";

type Action = (data: {
  args: string[];
  options: Record<string, string | boolean | number>;
}) => Promise<void>;

let logSpy: ReturnType<typeof vi.spyOn>;

/** A row as the model hands it back, with the columns the report prints. */
function row(fields: Record<string, unknown>) {
  return { id: fields.id, get: (key: string) => fields[key] };
}

beforeEach(() => {
  vi.clearAllMocks();
  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  findNeverExpiringTokens.mockResolvedValue({ accessTokens: [], refreshTokens: [] });
  purgeNeverExpiringTokens.mockResolvedValue({ accessTokens: 0, refreshTokens: 0 });
});

afterEach(() => {
  logSpy.mockRestore();
});

function loggedText(): string {
  return logSpy.mock.calls.map((call: unknown[]) => call.join(" ")).join("\n");
}

function action(): Action {
  return (registerAuthPurgeNeverExpiringCommand() as unknown as { action: Action }).action;
}

describe("registerAuthPurgeNeverExpiringCommand", () => {
  it("registers under the auth.purge-never-expiring name with a --dry-run option", () => {
    const cmd = registerAuthPurgeNeverExpiringCommand() as unknown as {
      name: string;
      options: { text: string }[];
    };

    expect(cmd.name).toBe("auth.purge-never-expiring");
    expect(cmd.options.map((option) => option.text)).toContain("--dry-run");
  });

  it("reports the clean case without deleting anything", async () => {
    await action()({ args: [], options: {} });

    expect(purgeNeverExpiringTokens).not.toHaveBeenCalled();
    expect(loggedText()).toContain("No never-expiring tokens found");
  });

  // The remediation's reason to exist: a row whose `expires_at` is an
  // `Invalid Date` is exactly what `auth.cleanup`'s `expires_at < now` cannot
  // select, so this is the case that proves the command reaches further.
  it("reports a row whose expires_at is an Invalid Date", async () => {
    findNeverExpiringTokens.mockResolvedValue({
      accessTokens: [
        row({ id: "at-1", user_id: 7, user_type: "user", expires_at: new Date("30dayz") }),
      ],
      refreshTokens: [],
    });
    purgeNeverExpiringTokens.mockResolvedValue({ accessTokens: 1, refreshTokens: 0 });

    await action()({ args: [], options: {} });

    const output = loggedText();

    expect(output).toContain("1 never-expiring token(s)");
    expect(output).toContain("access  id=at-1 user_id=7 user_type=user expires_at=Invalid Date");
    expect(output).toContain("Revoked 1 access token(s)");
  });

  it("reports refresh rows too", async () => {
    findNeverExpiringTokens.mockResolvedValue({
      accessTokens: [],
      refreshTokens: [
        row({ id: "rt-1", user_id: 9, user_type: "admin", expires_at: new Date("30dayz") }),
      ],
    });
    purgeNeverExpiringTokens.mockResolvedValue({ accessTokens: 0, refreshTokens: 1 });

    await action()({ args: [], options: {} });

    expect(loggedText()).toContain("refresh id=rt-1 user_id=9 user_type=admin");
  });

  it("never prints the token string — it is a live credential until it is deleted", async () => {
    findNeverExpiringTokens.mockResolvedValue({
      accessTokens: [
        row({
          id: "at-1",
          token: "a.live.credential",
          user_id: 7,
          user_type: "user",
          expires_at: new Date("30dayz"),
        }),
      ],
      refreshTokens: [],
    });

    await action()({ args: [], options: {} });

    expect(loggedText()).not.toContain("a.live.credential");
  });

  it("--dry-run reports the rows and deletes nothing", async () => {
    findNeverExpiringTokens.mockResolvedValue({
      accessTokens: [
        row({ id: "at-1", user_id: 7, user_type: "user", expires_at: new Date("30dayz") }),
      ],
      refreshTokens: [],
    });

    await action()({ args: [], options: { dryRun: true } });

    expect(purgeNeverExpiringTokens).not.toHaveBeenCalled();
    expect(loggedText()).toContain("Dry run");
  });

  // Fail-safe in the direction that matters: an ambiguous flag must not delete
  // live credentials. Only an explicit `--dry-run=false` proceeds.
  it("treats a stringly-typed --dry-run as a dry run", async () => {
    await action()({ args: [], options: { dryRun: "true" } });

    expect(purgeNeverExpiringTokens).not.toHaveBeenCalled();
  });

  it("honours an explicit --dry-run=false", async () => {
    findNeverExpiringTokens.mockResolvedValue({
      accessTokens: [
        row({ id: "at-1", user_id: 7, user_type: "user", expires_at: new Date("30dayz") }),
      ],
      refreshTokens: [],
    });

    await action()({ args: [], options: { dryRun: false } });

    expect(purgeNeverExpiringTokens).toHaveBeenCalledOnce();
  });
});
