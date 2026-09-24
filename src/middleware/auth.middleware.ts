import { config, type HttpContext, t, type Middleware } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import type {
  AuthCredentialDescriptor,
  AuthMiddlewareOptions,
  TokenFrom,
} from "../contracts/types";
import { authConfig } from "../services/auth-config";
import { readCredential, resolveRequestUserOutcome } from "../services/resolve-request-user";
import { AuthErrorCodes } from "../utils/auth-error-codes";
import {
  assertCsrfOriginAllowed,
  CsrfOriginMismatchError,
  requiresCsrfOriginCheck,
} from "./csrf-origin-check";
import { localizedLoginPath } from "./localized-login-path";

/** The 401 body shape every rejection in this middleware carries. */
type UnauthorizedPayload = { error: string; errorCode: string };

/**
 * Reject an unauthenticated request, choosing the representation by ROUTE KIND.
 *
 * An API route always gets the JSON 401 it has always gotten. A PAGE route
 * (`request.route.isPage` — the React-SSR pages) instead redirects a logged-out
 * browser to the configured login path with a `returnUrl`, so a human
 * navigating to a guarded page lands on the login screen rather than reading a
 * raw JSON error blob — the defect in finding b9ab9804.
 *
 * The redirect is OPT-IN and backward-compatible: with no `auth.pageAuth.loginPath`
 * configured, even a page route falls back to the JSON 401, so an app that has
 * not asked for page-login UX keeps exactly its current behavior. The API 401
 * contract is never changed for API routes.
 *
 * `returnUrl` carries `request.url` — the relative path + query the browser was
 * on — never the absolute URL: a relative target cannot be turned into an
 * open-redirect off this app's origin.
 */
function rejectUnauthorized(
  { request, response }: HttpContext,
  payload: UnauthorizedPayload,
  redirect?: AuthMiddlewareOptions["redirect"],
) {
  const loginPath = redirect?.to ?? authConfig.pageAuth.loginPath();
  const returnUrlParam = redirect?.returnUrlParam ?? authConfig.pageAuth.returnUrlParam();

  if (loginPath && request.route?.isPage) {
    // Under an active `web.localeRouting` strategy, the login destination
    // itself must carry the request's locale prefix — otherwise an anonymous
    // `/ar/admin` bounces to the DEFAULT locale's `/login` rather than
    // `/ar/login`, even though `returnUrl` below correctly points back at
    // `/ar/admin`. See `./localized-login-path.ts`.
    const destination = localizedLoginPath(loginPath, request.locale);
    const separator = destination.includes("?") ? "&" : "?";
    const returnUrl = encodeURIComponent(request.url);

    return response.redirect(`${destination}${separator}${returnUrlParam}=${returnUrl}`);
  }

  return response.unauthorized(payload);
}

function tokenFromDescriptor(descriptor: Partial<AuthCredentialDescriptor>): TokenFrom {
  if (!descriptor.source || descriptor.source === "header") return "header";

  if (!descriptor.key) {
    throw new Error("authMiddleware cookie credentials require a cookie key.");
  }

  return `cookie:${descriptor.key}`;
}

function resolveAllowedTypes(value: string | string[] | undefined): string[] {
  if (value !== undefined) return Array.isArray(value) ? value : [value];

  const configuredDefault = config.key("auth.defaultUserType") as string | undefined;

  if (configuredDefault) return [configuredDefault];

  const userTypes = config.key("auth.userType", {}) as Record<string, unknown>;
  const configuredTypes = Object.keys(userTypes);

  if (configuredTypes.length === 1) return configuredTypes;

  throw new Error(
    "authMiddleware requires a user type when auth.defaultUserType is unset and multiple user types exist.",
  );
}

/**
 * Build a route gate. Authentication is required unless optional is explicit.
 *
 * An omitted user type selects the configured default; an explicit argument
 * selects which user types may pass:
 * - `[]` — any authenticated user (token required, type not checked).
 * - `"admin"` / `["admin", "staff"]` — token required AND the user's
 *   `userType` must be one of the listed types.
 *
 * `{ optional: true }` allows anonymous requests. All other forms reject
 * missing or invalid credentials with 401, or a configured page redirect.
 *
 * `tokenFrom` selects one credential source and defaults to `"header"`.
 * A single source avoids making credential precedence depend on array order.
 *
 * @example
 * router.get("/account", authMiddleware([]), accountController);
 * router.get("/admin", authMiddleware("admin"), adminController);
 * router.get("/back-office", authMiddleware(["admin", "staff"]), backOfficeController);
 * router.get("/browser-account", authMiddleware([], "cookie:token"), accountController);
 */
export function authMiddleware(): Middleware;
export function authMiddleware(options: AuthMiddlewareOptions): Middleware;
export function authMiddleware(
  allowedUserType: string | string[],
  options?: AuthMiddlewareOptions,
): Middleware;
export function authMiddleware(
  allowedUserType: string | string[],
  tokenFrom?: TokenFrom,
): Middleware;
export function authMiddleware(
  userTypeOrOptions?: string | string[] | AuthMiddlewareOptions,
  legacyTokenFromOrOptions?: TokenFrom | AuthMiddlewareOptions,
): Middleware {
  const options =
    typeof userTypeOrOptions === "object" && !Array.isArray(userTypeOrOptions)
      ? userTypeOrOptions
      : typeof legacyTokenFromOrOptions === "object"
        ? legacyTokenFromOrOptions
        : undefined;
  const selectedUserType =
    typeof userTypeOrOptions === "string" || Array.isArray(userTypeOrOptions)
      ? userTypeOrOptions
      : undefined;
  const allowedTypes = resolveAllowedTypes(selectedUserType);
  const legacyTokenFrom =
    typeof legacyTokenFromOrOptions === "string" ? legacyTokenFromOrOptions : undefined;
  const dualSources = options?.sources?.length ? options.sources.map(tokenFromDescriptor) : undefined;

  if (dualSources && options?.source) {
    throw new Error("authMiddleware accepts either `source` or `sources`, not both.");
  }

  const dualHeader = dualSources?.includes("header") ?? false;
  const dualCookies = dualSources?.filter(source => source !== "header") ?? [];

  if (dualSources && (dualCookies.length > 1 || dualSources.length - dualCookies.length > 1)) {
    throw new Error("authMiddleware `sources` accepts at most one header and one cookie.");
  }

  // With dual sources the configured cookie is the base credential; the header
  // is chosen per request, ahead of it.
  const cookieTokenFrom: TokenFrom = dualSources
    ? (dualCookies[0] ?? "header")
    : options
      ? tokenFromDescriptor(options)
      : (legacyTokenFrom ?? "header");
  const tokenFrom = cookieTokenFrom;
  const refreshCredential = options?.refresh ? tokenFromDescriptor(options.refresh) : undefined;
  const renewalUserType = allowedTypes.length === 1 ? allowedTypes[0] : undefined;

  if (
    refreshCredential &&
    (tokenFrom === "header" || refreshCredential === "header" || !renewalUserType)
  ) {
    throw new Error(
      "authMiddleware automatic renewal requires one allowed user type and cookie access and refresh credentials.",
    );
  }

  const optional = options?.optional === true;

  const auth: Middleware = async ({ request, response }) => {
    const reject = (payload: UnauthorizedPayload) =>
      rejectUnauthorized({ request, response }, payload, options?.redirect);

    // A present Authorization header always wins and never falls back to the
    // cookie: the credential used is the header, so no renewal and no CSRF check.
    const headerWins = dualHeader && Boolean(request.authorizationValue);
    const usedTokenFrom: TokenFrom = headerWins ? "header" : tokenFrom;
    const usedRefresh = headerWins ? undefined : refreshCredential;

    // Renewal can mint cookies, so a cookie-authenticated unsafe request must
    // pass the same CSRF check even when its access cookie is missing.
    if (
      (readCredential(request, usedTokenFrom) || usedRefresh) &&
      requiresCsrfOriginCheck(usedTokenFrom, request.method)
    ) {
      try {
        assertCsrfOriginAllowed(request);
      } catch (error) {
        if (!(error instanceof CsrfOriginMismatchError)) throw error;

        log.error("http", "auth", error);
        return response.forbidden({
          error: t("auth.errors.csrfOriginMismatch"),
          errorCode: AuthErrorCodes.CsrfOriginMismatch,
        });
      }
    }

    const outcome = await resolveRequestUserOutcome(request, response, {
      tokenFrom: usedTokenFrom,
      refreshCredential: usedRefresh,
      overlapMs: options?.refresh?.overlapMs,
      allowedTypes,
      renewalUserType,
    });

    if (outcome.user) {
      request.locals.user = outcome.user;
      return;
    }

    if (outcome.failure === "forbidden") {
      return response.forbidden({
        error: t("auth.errors.unauthorized"),
        errorCode: AuthErrorCodes.Unauthorized,
      });
    }

    if (optional) return;

    if (outcome.failure === "missing") {
      return reject({
        error: t("auth.errors.missingAccessToken"),
        errorCode: AuthErrorCodes.MissingAccessToken,
      });
    }

    if (outcome.failure === "unauthorized") {
      return reject({
        error: t("auth.errors.unauthorized"),
        errorCode: AuthErrorCodes.Unauthorized,
      });
    }

    return reject({
      error: t("auth.errors.invalidAccessToken"),
      errorCode: AuthErrorCodes.InvalidAccessToken,
    });
  };

  return auth;
}
