import { describe, expect, it } from "vitest";
import type { AuthConfigurations, PageAuthConfig } from "./types";

/**
 * Compile-time guard for finding 7379944c: a typed `AuthConfigurations` must
 * accept `pageAuth`. The 5.8 runtime (`authConfig.pageAuth`) reads
 * `auth.pageAuth.loginPath`, and the upgrade checklist tells apps to set it —
 * but the type omitted `pageAuth`, so a consumer's `tsc` rejected it with TS2353
 * and the app build broke.
 *
 * This is a TYPE assertion, not a runtime check: if `pageAuth` is dropped from
 * `AuthConfigurations` (or its shape drifts), `tsc` fails to compile THIS file
 * with the exact consumer error. `@warlock.js/auth` has no `typecheck` script of
 * its own yet, so the verifying `tsc` run is manual/consumer-side — the red
 * control is: remove `pageAuth` from the type, run `tsc -p tsconfig.json`, watch
 * this assignment error TS2353; restore, and it compiles.
 */
const typedConfigWithPageAuth: AuthConfigurations = {
  userType: {},
  pageAuth: { loginPath: "/login", returnUrlParam: "returnUrl" },
};

// `loginPath` alone is valid (returnUrlParam is optional, defaults to "returnUrl").
const minimalPageAuth: PageAuthConfig = { loginPath: "/login" };

describe("AuthConfigurations declares pageAuth (7379944c)", () => {
  it("accepts a typed pageAuth config with loginPath + returnUrlParam", () => {
    expect(typedConfigWithPageAuth.pageAuth?.loginPath).toBe("/login");
    expect(typedConfigWithPageAuth.pageAuth?.returnUrlParam).toBe("returnUrl");
  });

  it("accepts pageAuth with loginPath only (returnUrlParam optional)", () => {
    expect(minimalPageAuth.returnUrlParam).toBeUndefined();
  });
});
