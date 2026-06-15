import { describe, expect, it } from "vitest";
import { AuthErrorCodes } from "./auth-error-codes";

/**
 * `AuthErrorCodes` is a WIRE CONTRACT: clients and error transformers map these
 * exact strings to user-facing messages. A value change here is a breaking
 * change, so this spec pins each code rather than trusting the enum to stay put.
 */
describe("AuthErrorCodes", () => {
  it("pins the published wire value of every code", () => {
    expect(AuthErrorCodes.MissingAccessToken).toBe("EC001");
    expect(AuthErrorCodes.InvalidAccessToken).toBe("EC002");
    expect(AuthErrorCodes.Unauthorized).toBe("EC003");
    expect(AuthErrorCodes.TooManyAttempts).toBe("EC004");
  });

  it("keeps every code unique", () => {
    const codes = Object.values(AuthErrorCodes);

    expect(new Set(codes).size).toBe(codes.length);
  });
});
