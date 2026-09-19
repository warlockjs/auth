import { resolveCsrfOriginVerdict, type Request } from "@warlock.js/core";
import type { TokenFrom } from "../contracts/types";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/** HTTP methods the CSRF Origin check exempts — reads, never state changes. */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Why {@link assertCsrfOriginAllowed} refused a request. */
export type CsrfOriginMismatchReason =
  | "origin-mismatch"
  | "referer-mismatch"
  | "missing-origin-and-referer";

/**
 * A cookie-authenticated, unsafe-method request whose `Origin`/`Referer`
 * failed the check. `reason` names exactly why,
 * so an error transformer or an incident log never has to string-match the
 * message.
 */
export class CsrfOriginMismatchError extends Error {
  readonly code = AuthErrorCodes.CsrfOriginMismatch;

  constructor(public readonly reason: CsrfOriginMismatchReason) {
    super(`CSRF Origin check failed: ${reason}`);
    this.name = "CsrfOriginMismatchError";
  }
}

/**
 * Whether a request is in scope for the CSRF Origin check at all — only a
 * `cookie:`-sourced credential on an unsafe method (POST/PUT/PATCH/DELETE) is.
 * Header-token auth and safe methods (GET/HEAD/OPTIONS) are always exempt:
 * only a cookie-sourced credential can be silently replayed cross-site by a
 * browser, so only it needs the check.
 */
export function requiresCsrfOriginCheck(tokenFrom: TokenFrom, method: string): boolean {
  return tokenFrom.startsWith("cookie:") && !SAFE_METHODS.has(method.toUpperCase());
}

/**
 * CSRF Origin check for a cookie-authenticated unsafe-method request (lead
 * decision 3). Allowed when `Origin` — or, when `Origin` is absent, `Referer`
 * — names the request's own origin or an entry in `auth.csrf.allowedOrigins`.
 * Throws {@link CsrfOriginMismatchError} otherwise, including when BOTH
 * headers are absent.
 *
 * Delegates the actual same-origin/allowedOrigins/trustProxy-aware
 * comparison to `@warlock.js/core`'s `resolveCsrfOriginVerdict`
 * (`core/src/http/csrf-origin-policy.ts`) — SECURITY card 8a752ab2 moved that
 * logic down into `core` so this middleware's check and core's own default
 * CSRF-Origin guard (`core/src/http/csrf-default-guard.ts`, which now runs
 * even earlier, ahead of this middleware, for cookie-carrying unsafe-method
 * requests generally) share one implementation instead of two copies that
 * could drift apart.
 *
 * Callers gate this behind {@link requiresCsrfOriginCheck} — this function
 * itself does not re-check the token source or the method.
 */
export function assertCsrfOriginAllowed(request: Request): void {
  const verdict = resolveCsrfOriginVerdict(request);

  if (!verdict.allowed) {
    throw new CsrfOriginMismatchError(verdict.reason);
  }
}
