import type { Request } from "@warlock.js/core";
import type { TokenFrom } from "../contracts/types";
import { authConfig } from "../services/auth-config";
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

/** The request's own origin — what an `Origin`/`Referer` header must match. */
function ownOrigin(request: Request): string {
  return `${request.protocol}://${request.hostname}`;
}

/** Extract `scheme://host` from a full URL (e.g. a `Referer` header value). */
function originOf(rawUrl: string): string | undefined {
  try {
    const url = new URL(rawUrl);

    return `${url.protocol}//${url.host}`;
  } catch {
    return undefined;
  }
}

/** Same-origin, or an explicit entry in `auth.csrf.allowedOrigins` (default `[]`). */
function isAllowedOrigin(origin: string, request: Request): boolean {
  if (origin === ownOrigin(request)) return true;

  return authConfig.csrf.allowedOrigins().includes(origin);
}

/**
 * CSRF Origin check for a cookie-authenticated unsafe-method request (lead
 * decision 3). Allowed when `Origin` — or, when `Origin` is absent, `Referer`
 * — names the request's own origin or an entry in `auth.csrf.allowedOrigins`.
 * Throws {@link CsrfOriginMismatchError} otherwise, including when BOTH
 * headers are absent.
 *
 * Callers gate this behind {@link requiresCsrfOriginCheck} — this function
 * itself does not re-check the token source or the method.
 */
export function assertCsrfOriginAllowed(request: Request): void {
  const origin = request.origin;

  if (origin) {
    if (isAllowedOrigin(origin, request)) return;

    throw new CsrfOriginMismatchError("origin-mismatch");
  }

  const referer = request.header("referer");
  const refererOrigin = typeof referer === "string" ? originOf(referer) : undefined;

  if (refererOrigin) {
    if (isAllowedOrigin(refererOrigin, request)) return;

    throw new CsrfOriginMismatchError("referer-mismatch");
  }

  throw new CsrfOriginMismatchError("missing-origin-and-referer");
}
