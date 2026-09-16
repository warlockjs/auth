import { describe, expect, it, vi } from "vitest";

// The package cannot be loaded at all in this file — the shape Node reports
// for an app that never installed the optional peer.
vi.mock("@warlock.js/notifications", () => {
  throw Object.assign(
    new Error("Cannot find package '@warlock.js/notifications' imported from app"),
    { code: "ERR_MODULE_NOT_FOUND" },
  );
});

vi.mock("@warlock.js/core", () => {
  class HttpError extends Error {
    public constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  }

  return {
    config: { key: (_key: string, fallback?: unknown) => fallback },
    HttpError,
    ServerError: class extends HttpError {
      public constructor(message: string) {
        super(500, message);
      }
    },
  };
});

vi.mock("@warlock.js/logger", () => ({ log: { warn: vi.fn(), error: vi.fn() } }));

import { NotificationsUnavailableError } from "../errors/notifications-unavailable.error";
import { resolveTokenNotification } from "./token-notifications";

describe("resolveTokenNotification without @warlock.js/notifications", () => {
  it("throws NotificationsUnavailableError naming the missing package, for both flows", async () => {
    for (const type of ["email-verification", "password-reset"] as const) {
      const error = await resolveTokenNotification(type).catch((caught) => caught);

      expect(error).toBeInstanceOf(NotificationsUnavailableError);
      expect(error.message).toContain("@warlock.js/notifications");
      expect(error.message).toContain("not installed");
    }
  });
});
